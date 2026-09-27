#define _XOPEN_SOURCE 700
#define _FILE_OFFSET_BITS 64
#include "config.h"
#include "disk.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum { sector = 512, sample = 1048576, esp_start = 4096,
       esp_sectors = 524288, root_start = 528384 };

struct disk_plan {
    char *image;
    uintmax_t device, inode, size, root_sectors;
    char head[65], tail[65];
};

static const char *value(const struct holy_config *c, const char *section,
                         const char *key)
{
    size_t i;
    for (i = 0; i < c->count; ++i)
        if (!strcmp(c->entries[i].section, section) &&
            !strcmp(c->entries[i].key, key)) return c->entries[i].values[0];
    return NULL;
}

static int number(const char *text, uintmax_t *out)
{
    char *end;
    if (!text || !*text || *text == '-' || *text == '+') return 0;
    errno = 0;
    *out = strtoumax(text, &end, 10);
    return !errno && !*end;
}

static int hash_region(int fd, off_t offset, char out[65])
{
    unsigned char data[16384], digest[32];
    static const char digits[] = "0123456789abcdef";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t total = 0, i;
    unsigned length = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && total < sample) {
        ssize_t got = pread(fd, data, sizeof data, offset + (off_t)total);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = 0; break; }
        ok = EVP_DigestUpdate(ctx, data, (size_t)got) == 1;
        total += (size_t)got;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) return 0;
    for (i = 0; i < 32; ++i) {
        out[2*i] = digits[digest[i] >> 4];
        out[2*i+1] = digits[digest[i] & 15];
    }
    out[64] = 0;
    return 1;
}

static int image_facts(int fd, struct disk_plan *p)
{
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < (off_t)(1ULL << 30) ||
        st.st_size % sector) return 0;
    p->device = (uintmax_t)st.st_dev;
    p->inode = (uintmax_t)st.st_ino;
    p->size = (uintmax_t)st.st_size;
    p->root_sectors = ((p->size / sector - root_start - 34) / 2048) * 2048;
    return p->root_sectors && hash_region(fd, 0, p->head) &&
           hash_region(fd, st.st_size - sample, p->tail);
}

static int quote(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (fputc('"', f) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', f) == EOF || fputc(*p, f) == EOF) return 0;
        } else if (*p < 32 || *p == 127) {
            if (fprintf(f, "\\x%02x", *p) < 0) return 0;
        } else if (fputc(*p, f) == EOF) return 0;
    }
    return fputc('"', f) != EOF;
}

static int sync_parent(const char *path)
{
    char *copy = strdup(path), *slash;
    int fd, ok;
    if (!copy) return 0;
    slash = strrchr(copy, '/');
    if (slash) {
        if (slash == copy) slash[1] = 0;
        else *slash = 0;
    } else { free(copy); copy = strdup("."); if (!copy) return 0; }
    fd = open(copy, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(copy);
    if (fd < 0) return 0;
    ok = !fsync(fd);
    if (close(fd)) ok = 0;
    return ok;
}

static int write_plan(const char *path, const struct disk_plan *p)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *f;
    int ok;
    if (fd < 0) { perror("holyinstall: plan"); return 1; }
    f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(path); return 1; }
    ok = fputs("[disk-plan]\nformat 1\nimage ", f) >= 0 && quote(f, p->image) &&
         fprintf(f, "\ndevice %" PRIuMAX "\ninode %" PRIuMAX
                 "\nsize %" PRIuMAX "\nroot-sectors %" PRIuMAX
                 "\nhead-sha256 %s\ntail-sha256 %s\n", p->device, p->inode,
                 p->size, p->root_sectors, p->head, p->tail) >= 0;
    if (fflush(f) || fsync(fd)) ok = 0;
    if (fclose(f)) ok = 0;
    if (ok) ok = sync_parent(path);
    if (!ok) { unlink(path); return 1; }
    return 0;
}

static int read_plan(const char *path, struct disk_plan *p)
{
    struct holy_config c = {0};
    const char *s;
    char *error = NULL;
    size_t i;
    int ok = holy_config_load_plan(path, &c, &error);
    if (!ok) { fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid plan"); free(error); return 2; }
    ok = c.count == 8;
    for (i = 0; i < c.count; ++i) if (strcmp(c.entries[i].section, "disk-plan")) ok = 0;
    s = value(&c, "disk-plan", "format");
    ok = ok && s && !strcmp(s, "1");
    s = value(&c, "disk-plan", "image");
    if (ok && s) p->image = strdup(s); else ok = 0;
    ok = ok && p->image && p->image[0] == '/';
    ok = ok && number(value(&c, "disk-plan", "device"), &p->device) &&
         number(value(&c, "disk-plan", "inode"), &p->inode) &&
         number(value(&c, "disk-plan", "size"), &p->size) &&
         number(value(&c, "disk-plan", "root-sectors"), &p->root_sectors);
    s = value(&c, "disk-plan", "head-sha256");
    if (ok && s && strlen(s) == 64) memcpy(p->head, s, 65); else ok = 0;
    s = value(&c, "disk-plan", "tail-sha256");
    if (ok && s && strlen(s) == 64) memcpy(p->tail, s, 65); else ok = 0;
    for (i = 0; ok && i < 64; ++i)
        if (!((p->head[i] >= '0' && p->head[i] <= '9') ||
              (p->head[i] >= 'a' && p->head[i] <= 'f')) ||
            !((p->tail[i] >= '0' && p->tail[i] <= '9') ||
              (p->tail[i] >= 'a' && p->tail[i] <= 'f'))) ok = 0;
    if (ok) ok = p->size >= (1ULL << 30) && p->size % sector == 0 &&
                 p->root_sectors == ((p->size / sector - root_start - 34) / 2048) * 2048;
    holy_config_free(&c);
    if (!ok) { fputs("holyinstall: invalid disk plan\n", stderr); return 2; }
    return 0;
}

static int child(const char *program, char *const args[], const char *input, int image_fd)
{
    pid_t pid;
    int status, pipefd[2] = {-1, -1};
    if (input && pipe(pipefd)) return 1;
    pid = fork();
    if (pid < 0) { if (pipefd[0] >= 0) { close(pipefd[0]); close(pipefd[1]); } return 1; }
    if (!pid) {
        if (image_fd >= 0 && (dup2(image_fd, 9) < 0 || fcntl(9, F_SETFD, 0) < 0)) _exit(127);
        if (input && (dup2(pipefd[0], 0) < 0)) _exit(127);
        if (pipefd[0] >= 0) close(pipefd[0]);
        if (pipefd[1] >= 0) close(pipefd[1]);
        execv(program, args);
        _exit(127);
    }
    if (input) {
        size_t len = strlen(input), used = 0;
        close(pipefd[0]);
        while (used < len) {
            ssize_t n = write(pipefd[1], input + used, len - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            used += (size_t)n;
        }
        close(pipefd[1]);
        if (used != len) { waitpid(pid, &status, 0); return 1; }
    }
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int loop_status(const char *image)
{
    int pipefd[2], status;
    pid_t pid;
    char byte;
    ssize_t got;
    char *const args[] = {"losetup", "-j", (char *)image, NULL};
    if (access("/sbin/losetup", X_OK) || pipe(pipefd)) return -1;
    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (!pid) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        close(pipefd[1]);
        execv("/sbin/losetup", args);
        _exit(127);
    }
    close(pipefd[1]);
    do { got = read(pipefd[0], &byte, 1); } while (got < 0 && errno == EINTR);
    close(pipefd[0]);
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    if (got < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) return -1;
    return got ? 1 : 0;
}

static int journal(const char *path, const char *stage, int first)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC |
                  (first ? O_CREAT | O_EXCL : 0), 0600);
    size_t len = strlen(stage);
    int ok;
    if (fd < 0) return 0;
    ok = write(fd, stage, len) == (ssize_t)len && write(fd, "\n", 1) == 1 && !fsync(fd);
    if (close(fd)) ok = 0;
    if (ok && first) ok = sync_parent(path);
    return ok;
}

static int disk_plan(const char *config_path, const char *plan_path)
{
    struct holy_config c = {0};
    struct disk_plan p = {0};
    const char *image, *layout;
    char *error = NULL;
    int fd, rc = 1;
    if (!holy_config_load(config_path, &c, &error)) {
        fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid config");
        free(error); return 2;
    }
    image = value(&c, "disk", "image");
    layout = value(&c, "disk", "layout");
    if (!image || !layout || strcmp(layout, "gpt-ext4")) { rc = 2; goto done; }
    p.image = realpath(image, NULL);
    if (!p.image) { perror("holyinstall: image"); rc = 6; goto done; }
    fd = open(p.image, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !image_facts(fd, &p)) {
        fputs("holyinstall: image must be a regular file of at least 1 GiB\n", stderr);
        if (fd >= 0) close(fd);
        rc = 6; goto done;
    }
    close(fd);
    if (loop_status(p.image)) {
        fputs("holyinstall: image is attached to a loop device or losetup is unavailable\n", stderr);
        rc = 6; goto done;
    }
    printf("disk image %s\nidentity %" PRIuMAX ":%" PRIuMAX " size %" PRIuMAX
           "\nGPT: BIOS 2048+2048; ESP %d+%d FAT32; root %d+%" PRIuMAX
           " ext4\nall existing data in this image will be destroyed\n",
           p.image, p.device, p.inode, p.size, esp_start, esp_sectors,
           root_start, p.root_sectors);
    rc = write_plan(plan_path, &p);
done:
    free(p.image); holy_config_free(&c);
    return rc;
}

static int disk_apply(const char *plan_path, const char *confirm)
{
    struct disk_plan p = {0}, actual = {0};
    char *journal_path = NULL, *script = NULL;
    char root_blocks[32], offset[64];
    int fd = -1, rc = read_plan(plan_path, &p), n;
    char *const partition[] = {"sfdisk", "--no-reread", "--no-tell-kernel", "/proc/self/fd/9", NULL};
    char *const verify[] = {"sfdisk", "--verify", "/proc/self/fd/9", NULL};
    char *const fat[] = {"mkfs.fat", "-F", "32", "-s", "4", "--offset=4096", "-n", "HOLYBOOT", "/proc/self/fd/9", "262144", NULL};
    char *const ext[] = {"mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-E", offset, "/proc/self/fd/9", root_blocks, NULL};
    if (rc) goto done;
    if (strcmp(confirm, p.image)) { fputs("holyinstall: confirmation must match image path\n", stderr); rc = 3; goto done; }
    fd = open(p.image, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) || !image_facts(fd, &actual)) { rc = 6; goto done; }
    if (actual.device != p.device || actual.inode != p.inode || actual.size != p.size ||
        strcmp(actual.head, p.head) || strcmp(actual.tail, p.tail)) {
        fputs("holyinstall: image changed since plan\n", stderr); rc = 3; goto done;
    }
    if (loop_status(p.image)) {
        fputs("holyinstall: image is attached to a loop device or losetup is unavailable\n", stderr);
        rc = 6; goto done;
    }
    journal_path = malloc(strlen(plan_path) + 9);
    if (!journal_path) { rc = 1; goto done; }
    sprintf(journal_path, "%s.journal", plan_path);
    if (access(journal_path, F_OK) == 0) {
        fputs("holyinstall: disk journal exists; inspect before recovery\n", stderr);
        rc = 5; goto done;
    }
    if (access("/usr/sbin/sfdisk", X_OK) || access("/sbin/mkfs.fat", X_OK) ||
        access("/sbin/mke2fs", X_OK)) {
        fputs("holyinstall: sfdisk, mkfs.fat and mke2fs are required\n", stderr);
        rc = 6; goto done;
    }
    n = snprintf(NULL, 0,
        "label: gpt\nunit: sectors\nfirst-lba: 2048\n"
        "start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649\n"
        "start=4096, size=524288, type=U\n"
        "start=528384, size=%" PRIuMAX ", type=L\n", p.root_sectors);
    script = malloc((size_t)n + 1);
    if (!script) { rc = 1; goto done; }
    snprintf(script, (size_t)n + 1,
        "label: gpt\nunit: sectors\nfirst-lba: 2048\n"
        "start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649\n"
        "start=4096, size=524288, type=U\n"
        "start=528384, size=%" PRIuMAX ", type=L\n", p.root_sectors);
    snprintf(root_blocks, sizeof root_blocks, "%" PRIuMAX, p.root_sectors / 8);
    snprintf(offset, sizeof offset, "offset=%" PRIuMAX, (uintmax_t)root_start * sector);
    if (!journal(journal_path, "prepared", 1)) { rc = 1; goto done; }
    rc = 5;
    if (!journal(journal_path, "partitioning", 0) ||
        child("/usr/sbin/sfdisk", partition, script, fd)) goto done;
    if (child("/usr/sbin/sfdisk", verify, NULL, fd)) goto done;
    if (!journal(journal_path, "partitioned", 0) ||
        !journal(journal_path, "formatting-esp", 0) ||
        child("/sbin/mkfs.fat", fat, NULL, fd)) goto done;
    if (!journal(journal_path, "formatted-esp", 0) ||
        !journal(journal_path, "formatting-root", 0) ||
        child("/sbin/mke2fs", ext, NULL, fd)) goto done;
    if (fsync(fd) || !journal(journal_path, "committed", 0)) goto done;
    puts("disk image prepared; mount and package installation remain separate steps");
    rc = 0;
done:
    if (rc == 5) fputs("holyinstall: disk mutation may be partial; inspect journal and image\n", stderr);
    if (fd >= 0) close(fd);
    free(script); free(journal_path); free(p.image);
    return rc;
}

int holy_disk_main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[0], "plan") &&
        !strcmp(argv[1], "--config") && !strcmp(argv[3], "--output"))
        return disk_plan(argv[2], argv[4]);
    if (argc == 5 && !strcmp(argv[0], "apply") &&
        !strcmp(argv[1], "--plan") && !strcmp(argv[3], "--confirm"))
        return disk_apply(argv[2], argv[4]);
    fputs("usage: holyinstall disk plan --config FILE --output NEW_PLAN | "
          "holyinstall disk apply --plan PLAN --confirm IMAGE\n", stderr);
    return 2;
}
