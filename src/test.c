#define _XOPEN_SOURCE 700
#include "test.h"
#include "cache.h"
#include "install.h"
#include "package.h"
#include "repo.h"
#include "source.h"
#include "state.h"
#include "trial.h"
#include "up.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define TEST_LIMIT (24u)

/* one check of the requested set. every result is a fact about a bound input of the
   saved plan, never a claim that the plan installs or runs anything. */
struct test_check {
    const char *code;
    const char *result;
    const char *detail;
};

struct test_run {
    const char *root;
    const char *mode;
    int json;
    struct test_check checks[TEST_LIMIT];
    size_t count;
    size_t pass, fail, skip, unknown;
};

struct test_observed {
    const char *digest;
    int found;
    int payload;        /* -2 no installed slot, -1 unreadable manifest, 0 drift, 1 intact */
    char **digests;
    size_t count;
    size_t capacity;
    int overflow;
};

static int sha256_hex(const void *data, size_t size, char output[65])
{
    unsigned char bytes[32];
    unsigned int length;
    size_t i;
    if (EVP_Digest(data, size, bytes, &length, EVP_sha256(), NULL) != 1 || length != 32)
        return 0;
    for (i = 0; i < 32; ++i) snprintf(output + 2 * i, 3, "%02x", bytes[i]);
    output[64] = 0;
    return 1;
}

static void print_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32 || *p >= 127) printf("\\u%04x", (unsigned int)*p);
        else putchar(*p);
    }
    putchar('"');
}

/* the installed set is the trial base a root test runs against. a live rootfs has no
   stable whole-tree digest, so the binding is its generation and its artifact set in
   the artifact order the state visit already guarantees. */
static int observed_visit(void *context, int root, int instance, const char *digest)
{
    struct test_observed *state = context;
    char **grown;
    int files;
    if (state->digest && !strcmp(digest, state->digest)) {
        state->found = 1;
        files = openat(instance, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (files < 0) state->payload = -1;
        else {
            state->payload = holy_install_check_manifest(files, root);
            close(files);
        }
    }
    if (state->count >= state->capacity) {
        size_t capacity = state->capacity ? state->capacity * 2 : 32;
        if (capacity > 65536) { state->overflow = 1; return 0; }
        grown = realloc(state->digests, capacity * sizeof *grown);
        if (!grown) { state->overflow = 1; return 0; }
        state->digests = grown;
        state->capacity = capacity;
    }
    if (!(state->digests[state->count] = strdup(digest))) { state->overflow = 1; return 0; }
    ++state->count;
    return 0;
}

static void observed_forget(struct test_observed *state)
{
    size_t i;
    for (i = 0; i < state->count; ++i) free(state->digests[i]);
    free(state->digests);
    state->digests = NULL;
    state->count = 0;
    state->capacity = 0;
}

static int observed_binding(const struct test_observed *state, char output[65])
{
    char *joined;
    size_t i, used = 0;
    int ok = 0;
    joined = malloc(state->count * 65 + 1);
    if (!joined) return 0;
    for (i = 0; i < state->count; ++i) {
        memcpy(joined + used, state->digests[i], 64);
        used += 64;
        joined[used++] = '\n';
    }
    joined[used] = 0;
    ok = sha256_hex(joined, used, output);
    free(joined);
    return ok;
}

static void emit(const char *type, const char *first_key, const char *first_value,
                 const char *second_key, const char *second_value)
{
    printf("{\"schema\":\"holy-test-report-1\",\"type\":");
    print_string(type);
    if (first_key) {
        printf(",\"%s\":", first_key);
        print_string(first_value);
    }
    if (second_key) {
        printf(",\"%s\":", second_key);
        print_string(second_value);
    }
    printf("}\n");
}

static void record(struct test_run *run, const char *code, const char *result,
                   const char *detail)
{
    struct test_check *check;
    if (run->count >= TEST_LIMIT) return;
    check = &run->checks[run->count++];
    check->code = code;
    check->result = result;
    check->detail = detail;
    if (!strcmp(result, "pass")) ++run->pass;
    else if (!strcmp(result, "fail")) ++run->fail;
    else if (!strcmp(result, "skip")) ++run->skip;
    else ++run->unknown;
    if (run->json) {
        printf("{\"schema\":\"holy-test-report-1\",\"type\":\"check\",\"check\":");
        print_string(code);
        printf(",\"result\":");
        print_string(result);
        if (detail) {
            printf(",\"detail\":");
            print_string(detail);
        }
        printf("}\n");
        return;
    }
    printf("test-check %s %s", code, result);
    if (detail) printf(" detail %s", detail);
    putchar('\n');
}

/* one cached archive usable for the plan, with the reason when it is not. a slot
   comparison proves the new artifact fills the planned slot, not merely that it
   verifies. */
static int archived(const char *digest, const char *root,
                    const struct holy_package_identity *slot, const char **reason)
{
    char *snapshot;
    struct holy_package_identity identity = {0};
    int ok;
    snapshot = holy_cache_snapshot(digest, root);
    if (!snapshot) { *reason = "archive-unavailable"; return 0; }
    ok = holy_package_identity(snapshot, &identity) && !strcmp(identity.digest, digest);
    unlink(snapshot);
    free(snapshot);
    if (!ok) { *reason = "archive-unverified"; holy_package_identity_free(&identity); return 0; }
    if (slot && (strcmp(identity.name, slot->name) || strcmp(identity.os, slot->os) ||
                 strcmp(identity.arch, slot->arch) || strcmp(identity.libc, slot->libc) ||
                 strcmp(identity.version_family, slot->version_family))) {
        *reason = "slot-mismatch";
        holy_package_identity_free(&identity);
        return 0;
    }
    holy_package_identity_free(&identity);
    *reason = NULL;
    return 1;
}

int holy_test_command(int argc, char **argv)
{
    const char *mode = "root", *root = "/", *approved = NULL, *plan_path = NULL;
    const char *reason = NULL;
    struct holy_up_plan plan = {0};
    struct holy_package_identity old_identity = {0};
    struct test_observed observed = {NULL, 0, -2, NULL, 0, 0, 0};
    struct test_run run = {NULL, NULL, 0, {{NULL, NULL, NULL}}, 0, 0, 0, 0, 0};
    char index[65], source_id[65], slot[65], binding[65];
    unsigned long long generation = 0;
    char *old_snapshot = NULL;
    int dir = -1, status = 0, i, read, command = -1, shell = 0;

    for (i = 0; i < argc; ++i) {
        const char *option = argv[i];
        if (command < 0 && !strcmp(option, "--")) { command = i + 1; break; }
        if (command < 0 && !plan_path && option[0] != '-') { plan_path = option; continue; }
        if (!strcmp(option, "--sha256") && i + 1 < argc && !approved) { approved = argv[++i]; continue; }
        if (!strcmp(option, "--root") && i + 1 < argc) { root = argv[++i]; continue; }
        if (!strcmp(option, "--mode") && i + 1 < argc) { mode = argv[++i]; continue; }
        if (!strcmp(option, "--json")) { run.json = 1; continue; }
        if (!strcmp(option, "--shell") && !shell && !command) { shell = 1; continue; }
        status = 2;
        goto usage;
    }
    if (shell && command >= 0) { status = 2; goto usage; }
    if (command >= 0 && !command) { status = 2; goto usage; }
    if ((command >= 0 || shell) && strcmp(mode, "root")) { status = 2; goto usage; }
    if (!plan_path || !*root || (strcmp(mode, "root") && strcmp(mode, "vm"))) {
        status = 2;
        goto usage;
    }
    run.root = root;
    run.mode = mode;

    read = holy_up_plan_read(plan_path, approved, &plan);
    if (read == 2) fprintf(stderr, "holypkg: malformed update plan\n");
    else if (read == 3) fprintf(stderr, "holypkg: plan digest differs from the approved one\n");
    else if (read) fprintf(stderr, "holypkg: update plan unavailable\n");
    if (read) { status = read; goto done; }
    observed.digest = plan.old_digest;

    if (run.json) {
        printf("{\"schema\":\"holy-test-report-1\",\"type\":\"plan\",\"plan\":");
        print_string(plan.hash);
        printf(",\"mode\":");
        print_string(mode);
        printf(",\"source\":");
        print_string(plan.source_id);
        printf(",\"alias\":");
        print_string(plan.alias);
        printf(",\"catalog\":");
        print_string(plan.catalog);
        printf(",\"index\":");
        print_string(plan.index);
        printf(",\"old\":");
        print_string(plan.old_digest);
        printf(",\"new\":");
        print_string(plan.new_digest);
        printf(",\"state-plan\":");
        print_string(plan.state_plan);
        printf(",\"coverage\":\"plan-inputs\"}\n");
    } else {
        printf("test-plan %s mode %s\n", plan.hash, mode);
        printf("test-input source %s alias \"%s\"\n", plan.source_id, plan.alias);
        printf("test-input catalog \"%s\" index %s\n", plan.catalog, plan.index);
        printf("test-input old %s new %s state-plan %s\n",
               plan.old_digest, plan.new_digest, plan.state_plan);
    }
    index[0] = source_id[0] = slot[0] = binding[0] = 0;

    record(&run, "plan-document", "pass", NULL);

    /* the trial base: the installed set for a root test, and none for a VM trial that
       owns its own image, which the runner measures as it copies that image. */
    if (!strcmp(mode, "root") &&
        !holy_state_visit(root, observed_visit, &observed, &generation) &&
        !observed.overflow && observed_binding(&observed, binding)) {
        if (run.json) {
            printf("{\"schema\":\"holy-test-report-1\",\"type\":\"image\",\"mode\":\"root\",\"generation\":%llu,\"digest\":",
                   generation);
            print_string(binding);
            printf("}\n");
        } else printf("test-image rootfs generation %llu digest %s\n", generation, binding);
    } else if (run.json)
        printf("{\"schema\":\"holy-test-report-1\",\"type\":\"image\",\"mode\":\"%s\",\"image\":null,\"reason\":\"no-image-binding\"}\n",
               mode);
    else printf("test-image %s none reason %s\n", mode,
                strcmp(mode, "root") ? "no-vm-runner" : "no-image-binding");

    if (holy_source_active_id(root, plan.alias, source_id))
        record(&run, "source-binding", "fail", "no-active-source");
    else if (strcmp(plan.source_id, source_id))
        record(&run, "source-binding", "fail", "source-id-changed");
    else if (holy_source_catalog(root, plan.alias, plan.catalog, source_id))
        record(&run, "source-binding", "fail", "catalog-not-sealed-for-source");
    else
        record(&run, "source-binding", "pass", NULL);

    dir = open(plan.catalog, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_SH))
        record(&run, "catalog-generation", "fail", "catalog-unavailable");
    else if (!holy_repo_catalog_index(plan.catalog, index))
        record(&run, "catalog-generation", "fail", "catalog-unverified");
    else if (strcmp(index, plan.index))
        record(&run, "catalog-generation", "fail", "catalog-generation-changed");
    else
        record(&run, "catalog-generation", "pass", NULL);

    old_snapshot = holy_cache_snapshot(plan.old_digest, root);
    if (old_snapshot && holy_package_identity(old_snapshot, &old_identity) &&
        !strcmp(old_identity.digest, plan.old_digest))
        record(&run, "old-archive", "pass", NULL);
    else
        record(&run, "old-archive", "fail",
               old_snapshot ? "old-identity-mismatch" : "old-archive-unavailable");

    if (!old_identity.name)
        record(&run, "slot-candidate", "skip", "no-old-identity");
    else {
        read = dir >= 0 ? holy_repo_catalog_slot_digest(plan.catalog, &old_identity,
                                                        plan.new_digest, slot) : 6;
        if (read == 0 && !strcmp(slot, plan.index))
            record(&run, "slot-candidate", "pass", NULL);
        else if (read == 3)
            record(&run, "slot-candidate", "fail", "prepared-artifact-absent-from-slot");
        else
            record(&run, "slot-candidate", "fail", "slot-unverified");
    }

    if (archived(plan.new_digest, root, old_identity.name ? &old_identity : NULL, &reason))
        record(&run, "new-archive", "pass", NULL);
    else
        record(&run, "new-archive", "fail", reason);

    read = holy_state_visit(root, observed_visit, &observed, &generation);
    if (read == 5)
        record(&run, "installed-slot", "unknown", "unfinished-transaction");
    else if (read)
        record(&run, "installed-slot", "unknown", "database-unreadable");
    else if (!observed.found)
        record(&run, "installed-slot", "fail", "old-artifact-not-installed");
    else
        record(&run, "installed-slot", "pass", NULL);
    if (observed.payload == 1) record(&run, "installed-payload", "pass", NULL);
    else if (observed.payload == 0) record(&run, "installed-payload", "fail", "changed-payload");
    else if (observed.payload == -1)
        record(&run, "installed-payload", "fail", "invalid-installed-manifest");
    else record(&run, "installed-payload", "skip", "no-installed-slot");

    if (!strcmp(mode, "vm")) record(&run, "vm-trial", "unknown", "no-vm-runner");
    record(&run, "runtime-probes", "skip", "explicit-probe-request");

    if (strcmp(plan.accept_arch, "-")) {
        if (run.json) emit("override", "kind", "accept-arch", "artifact", plan.accept_arch);
        else printf("test-override accept-arch %s\n", plan.accept_arch);
    }
    if (strcmp(plan.accept_privileged, "-")) {
        if (run.json) emit("override", "kind", "accept-privileged", "artifact", plan.accept_privileged);
        else printf("test-override accept-privileged %s\n", plan.accept_privileged);
    }
    for (i = 0; (size_t)i < run.count; ++i) {
        const struct test_check *check = &run.checks[i];
        if (strcmp(check->result, "skip") && strcmp(check->result, "unknown")) continue;
        if (run.json) emit("unexecuted", "check", check->code, "reason",
                           check->detail ? check->detail : "none");
        else printf("test-unexecuted %s reason %s\n", check->code,
                    check->detail ? check->detail : "none");
    }
    if (run.json)
        printf("{\"schema\":\"holy-test-report-1\",\"type\":\"summary\",\"pass\":%zu,\"fail\":%zu,\"skip\":%zu,\"unknown\":%zu,\"coverage\":\"plan-inputs\"}\n",
               run.pass, run.fail, run.skip, run.unknown);
    else
        printf("test-report pass %zu fail %zu skip %zu unknown %zu coverage plan-inputs\n",
               run.pass, run.fail, run.skip, run.unknown);
    /* a failed check contradicts a bound input, an unexecuted one needs a capability
       this command does not have, and a skip that was not requested fails nothing. */
    status = run.unknown ? 6 : run.fail ? 4 : 0;
    if (ferror(stdout)) status = 1;
    /* a probe runs only against a requested set that completed, and a vm trial has no
       place to run a command of the running root. */
    if (!status && (command >= 0 || shell)) {
        char *fallback[] = {(char *)"/bin/sh", NULL};
        char **selected = fallback;
        const char *named = shell ? getenv("SHELL") : NULL;
        if (shell && named && *named) {
            fallback[0] = (char *)named;
        } else if (command >= 0) {
            selected = &argv[command];
        } else {
            status = 2;
        }
        if (!status) status = holy_trial_command(selected);
    }
done:
    if (status == 2) goto usage;
    if (old_snapshot) { unlink(old_snapshot); free(old_snapshot); }
    if (dir >= 0) close(dir);
    holy_package_identity_free(&old_identity);
    observed_forget(&observed);
    holy_up_plan_free(&plan);
    return status;
usage:
    fputs("usage: holypkg test PLAN [--sha256 PLAN_SHA256] [--mode root|vm] [--root DIRECTORY] [--json] [--shell | -- COMMAND [ARGS...]]\n", stderr);
    return status ? status : 2;
}
