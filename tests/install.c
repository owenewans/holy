#define _POSIX_C_SOURCE 200809L
#include "install.h"
#include "verify.h"
#include "change.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define require(condition) do { if (!(condition)) { fprintf(stderr, "transition fixture failed at line %d\n", __LINE__); return 0; } } while (0)

static int payload(int root, const char *path, const char *text)
{
    int fd = openat(root, path, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) { close(fd); return -1; }
    return fd;
}

static int file_is(int root, const char *path, const char *text, unsigned mode)
{
    struct stat st;
    char buffer[128];
    int fd = openat(root, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC), ok;
    if (fd < 0) return 0;
    ok = !fstat(fd, &st) && (st.st_mode & 07777) == mode &&
         read(fd, buffer, sizeof buffer) == (ssize_t)strlen(text) && !memcmp(buffer, text, strlen(text));
    close(fd);
    return ok;
}

static int transitions(int root, int resume)
{
    struct holy_manifest_entry old = {0}, next, link, added, invalid;
    unsigned char old_hash[32], new_hash[32];
    unsigned length;
    int first, second, fd;
    struct stat st;
    require(EVP_Digest("old", 3, old_hash, &length, EVP_sha256(), NULL) == 1 && length == 32);
    require(EVP_Digest("new payload", 11, new_hash, &length, EVP_sha256(), NULL) == 1 && length == 32);
    old.path = "data/current"; old.hash = old_hash; old.size = 3; old.mode = 0600;
    old.uid = (long long)geteuid(); old.gid = (long long)getegid();
    next = old; next.hash = new_hash; next.size = 11; next.mode = 0755;
    if (resume == 1) return holy_install_transition(root, &old, &next, ".holy-update-next") &&
                            file_is(root, old.path, "new payload", 0755);
    if (resume == 2) return holy_install_transition(root, NULL, &old, ".holy-update-first") &&
                            file_is(root, old.path, "old", 0600);
    require(!mkdirat(root, "data", 0700));
    first = payload(root, "first", "old");
    second = payload(root, "second", "new payload");
    require(first >= 0 && second >= 0);
    require(holy_install_transition_check(root, NULL, &old, 0));
    require(holy_install_prepare_file(root, &old, first, ".holy-update-first"));
    require(!fstatat(root, "data/.holy-update-first", &st, AT_SYMLINK_NOFOLLOW));
    require(fstatat(root, "data/current", &st, AT_SYMLINK_NOFOLLOW));
    require(holy_install_transition(root, NULL, &old, ".holy-update-first"));
    require(file_is(root, old.path, "old", 0600));
    require(!holy_install_transition_check(root, NULL, &old, 0));
    require(holy_install_transition_check(root, NULL, &old, 1));
    require(holy_install_transition(root, NULL, &old, ".holy-update-first"));
    require(!holy_install_prepare_file(root, &next, first, ".holy-update-bad-size"));
    invalid = next; invalid.hash = old_hash;
    require(!holy_install_prepare_file(root, &invalid, second, ".holy-update-bad-hash"));
    require(fstatat(root, "data/.holy-update-bad-hash", &st, AT_SYMLINK_NOFOLLOW));
    require(holy_install_prepare_file(root, &next, second, ".holy-update-next"));
    require(file_is(root, old.path, "old", 0600));
    require(holy_install_transition_check(root, &old, &next, 0));
    require(holy_install_transition(root, &old, &next, ".holy-update-next"));
    require(file_is(root, old.path, "new payload", 0755));
    require(!holy_install_transition_check(root, &old, &next, 0));
    require(holy_install_transition(root, &old, &next, ".holy-update-next"));
    require(holy_install_prepare_file(root, &next, second, ".holy-update-repeated"));
    require(holy_install_transition(root, &old, &next, ".holy-update-repeated"));
    require(fstatat(root, "data/.holy-update-repeated", &st, AT_SYMLINK_NOFOLLOW));
    link = next; link.link = "../second"; link.hash = NULL; link.size = 0; link.mode = 0777;
    require(holy_install_prepare_file(root, &link, -1, ".holy-update-link"));
    require(holy_install_transition(root, &next, &link, ".holy-update-link"));
    require(!fstatat(root, link.path, &st, AT_SYMLINK_NOFOLLOW) && S_ISLNK(st.st_mode));
    require(holy_install_prepare_file(root, &old, first, ".holy-update-regular"));
    require(holy_install_transition(root, &link, &old, ".holy-update-regular"));
    require(file_is(root, old.path, "old", 0600));
    require(holy_install_transition(root, &old, NULL, NULL));
    require(!holy_install_transition_check(root, &old, NULL, 0));
    require(holy_install_transition(root, &old, NULL, NULL));
    added = old; added.path = "data/added";
    require(holy_install_prepare_file(root, &added, first, ".holy-update-added"));
    fd = payload(root, added.path, "unexpected"); require(fd >= 0); close(fd);
    require(!holy_install_transition(root, NULL, &added, ".holy-update-added"));
    require(file_is(root, added.path, "unexpected", 0600));
    require(!unlinkat(root, added.path, 0));
    require(holy_install_transition(root, NULL, &added, ".holy-update-added"));
    next.path = added.path;
    require(holy_install_prepare_file(root, &next, second, ".holy-update-drift"));
    fd = payload(root, added.path, "drift"); require(fd >= 0); close(fd);
    require(!holy_install_transition(root, &added, &next, ".holy-update-drift"));
    require(file_is(root, added.path, "drift", 0600));
    require(!holy_install_prepare_file(root, &next, second, "../escape"));
    require(!holy_install_prepare_file(root, &next, second, "added"));
    invalid = next; invalid.path = "../escape";
    require(!holy_install_prepare_file(root, &invalid, second, ".holy-update-escape"));
    invalid = link; invalid.link = "../../escape";
    require(!holy_install_prepare_file(root, &invalid, -1, ".holy-update-escape"));
    require(!symlinkat("data", root, "alias"));
    invalid = next; invalid.path = "alias/escape";
    require(!holy_install_prepare_file(root, &invalid, second, ".holy-update-escape"));
    require(!symlinkat("../first", root, "data/.holy-update-owned"));
    require(!holy_install_prepare_file(root, &next, second, ".holy-update-owned"));
    require(file_is(root, "first", "old", 0600));
    close(first); close(second);
    return 1;
}

int main(int argc, char **argv)
{
    int root, ok;
    if (argc == 5 && (!strcmp(argv[1], "--file-plan") || !strcmp(argv[1], "--file-plan-recovery"))) {
        struct holy_file_plan plan = {0};
        char *record = NULL;
        size_t size = 0, failed = 0;
        int status = 2;
        root = open(argv[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root >= 0 && holy_file_plan_collect(argv[2], argv[3], &plan) &&
            holy_file_plan_record(&plan, &record, &size)) {
            status = holy_file_plan_check(&plan, root, !strcmp(argv[1], "--file-plan-recovery"), &failed);
            if (fwrite(record, 1, size, stdout) != size) status = 1;
            if (status) fprintf(stderr, "file-plan status %d change %zu\n", status, failed);
        }
        free(record); holy_file_plan_free(&plan);
        if (root >= 0) close(root);
        return status;
    }
    if (argc != 3) return 2;
    if (strcmp(argv[1], "--transitions") && strcmp(argv[1], "--resume-transition") &&
        strcmp(argv[1], "--resume-addition") &&
        !holy_verify_with_output(argv[1], 0)) return 2;
    root = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return 2;
    ok = !strcmp(argv[1], "--transitions") ? transitions(root, 0) :
         !strcmp(argv[1], "--resume-transition") ? transitions(root, 1) :
         !strcmp(argv[1], "--resume-addition") ? transitions(root, 2) :
         holy_install_preflight(argv[1], root) && holy_install_payload(argv[1], root);
    close(root);
    return ok ? 0 : 4;
}
