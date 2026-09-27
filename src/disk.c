#define _XOPEN_SOURCE 700
#define _FILE_OFFSET_BITS 64
#include "config.h"
#include "disk.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

enum { sector = 512, sample = 1048576, esp_start = 4096,
       esp_sectors = 524288, root_start = 528384 };

struct disk_plan {
    char *image;
    uintmax_t device, inode, size, root_sectors;
    char head[65], tail[65];
    int block;
    uintmax_t rdev;
    char serial[128];
    char tools[4][65];
};

static const char *const block_tools[] = {
    "/usr/bin/sfdisk", "/usr/bin/mkfs.fat", "/usr/bin/mke2fs", "/usr/bin/limine"
};
static const char *const block_tool_keys[] = {
    "sfdisk-sha256", "mkfs-fat-sha256", "mke2fs-sha256", "limine-sha256"
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

static int hash_span(int fd, uintmax_t offset, uintmax_t size, char out[65])
{
    unsigned char data[1048576], digest[32];
    static const char digits[] = "0123456789abcdef";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned length = 0;
    size_t i;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && size) {
        size_t want = size < sizeof data ? (size_t)size : sizeof data;
        ssize_t got = pread(fd, data, want, (off_t)offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = 0; break; }
        ok = EVP_DigestUpdate(ctx, data, (size_t)got) == 1;
        offset += (uintmax_t)got;
        size -= (uintmax_t)got;
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

static int sysfs_serial(dev_t device, char out[128])
{
    char path[128];
    const char *suffixes[] = { "/serial", "/device/serial" };
    size_t i;
    for (i = 0; i < sizeof suffixes / sizeof *suffixes; ++i) {
        FILE *input;
        size_t length, j;
        int complete;
        int n = snprintf(path, sizeof path, "/sys/dev/block/%u:%u%s",
                         major(device), minor(device), suffixes[i]);
        if (n < 0 || (size_t)n >= sizeof path) return 0;
        input = fopen(path, "r");
        if (!input) continue;
        if (!fgets(out, 128, input)) { fclose(input); continue; }
        complete = strchr(out, '\n') != NULL || feof(input);
        fclose(input);
        if (!complete) return 0;
        length = strlen(out);
        while (length && (out[length - 1] == '\n' || out[length - 1] == '\r'))
            out[--length] = 0;
        if (length) {
            for (j = 0; j < length; ++j)
                if ((unsigned char)out[j] < 32 || (unsigned char)out[j] > 126)
                    return 0;
            return 1;
        }
    }
    return 0;
}

static int block_facts(int fd, struct disk_plan *p)
{
    struct stat st;
    unsigned long long bytes;
    int logical;
    char partition[128];
    int n;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) ||
        ioctl(fd, (int)BLKGETSIZE64, &bytes) || ioctl(fd, BLKSSZGET, &logical) ||
        logical != sector || bytes < (1ULL << 30) ||
        bytes > INT64_MAX || bytes % sector) return 0;
    n = snprintf(partition, sizeof partition, "/sys/dev/block/%u:%u/partition",
                 major(st.st_rdev), minor(st.st_rdev));
    if (n < 0 || (size_t)n >= sizeof partition || !access(partition, F_OK)) return 0;
    p->device = (uintmax_t)st.st_dev;
    p->inode = (uintmax_t)st.st_ino;
    p->rdev = (uintmax_t)st.st_rdev;
    p->size = (uintmax_t)bytes;
    p->root_sectors = ((p->size / sector - root_start - 34) / 2048) * 2048;
    return p->root_sectors && sysfs_serial(st.st_rdev, p->serial) &&
           hash_region(fd, 0, p->head) &&
           hash_region(fd, (off_t)(p->size - sample), p->tail);
}

static int tool_hash(const char *path, char out[65])
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int ok = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
             st.st_size > 0 && (uintmax_t)st.st_size <= SIZE_MAX &&
             hash_span(fd, 0, (uintmax_t)st.st_size, out);
    if (fd >= 0) close(fd);
    return ok;
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
    ok = fprintf(f, "[disk-plan]\nformat %d\nimage ", p->block ? 2 : 1) >= 0 &&
         quote(f, p->image) &&
         fprintf(f, "\ndevice %" PRIuMAX "\ninode %" PRIuMAX
                 "\nsize %" PRIuMAX "\nroot-sectors %" PRIuMAX
                 "\nhead-sha256 %s\ntail-sha256 %s\n", p->device, p->inode,
                 p->size, p->root_sectors, p->head, p->tail) >= 0;
    if (ok && p->block) {
        size_t i;
        ok = fputs("kind block\nserial ", f) >= 0 && quote(f, p->serial) &&
             fprintf(f, "\nrdev %" PRIuMAX "\n", p->rdev) >= 0;
        for (i = 0; ok && i < 4; ++i)
            ok = fprintf(f, "%s %s\n", block_tool_keys[i], p->tools[i]) >= 0;
    }
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
    s = value(&c, "disk-plan", "format");
    p->block = s && !strcmp(s, "2");
    ok = s && (!strcmp(s, "1") || p->block) &&
         c.count == (size_t)(p->block ? 15 : 8);
    for (i = 0; i < c.count; ++i) if (strcmp(c.entries[i].section, "disk-plan")) ok = 0;
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
    if (ok && p->block) {
        s = value(&c, "disk-plan", "kind");
        ok = s && !strcmp(s, "block") &&
             !strncmp(p->image, "/dev/", 5) &&
             number(value(&c, "disk-plan", "rdev"), &p->rdev);
        s = value(&c, "disk-plan", "serial");
        if (!s || !*s || strlen(s) >= sizeof p->serial) ok = 0;
        else {
            strcpy(p->serial, s);
            for (i = 0; i < strlen(s); ++i)
                if ((unsigned char)s[i] < 32 || (unsigned char)s[i] > 126) ok = 0;
        }
        for (i = 0; i < 4; ++i) {
            size_t j;
            s = value(&c, "disk-plan", block_tool_keys[i]);
            if (!s || strlen(s) != 64) { ok = 0; continue; }
            memcpy(p->tools[i], s, 65);
            for (j = 0; j < 64; ++j)
                if (!((s[j] >= '0' && s[j] <= '9') ||
                      (s[j] >= 'a' && s[j] <= 'f'))) ok = 0;
        }
    }
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
    const char *image, *device, *layout;
    char *error = NULL;
    int fd, rc = 1;
    if (!holy_config_load(config_path, &c, &error)) {
        fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid config");
        free(error); return 2;
    }
    image = value(&c, "disk", "image");
    device = value(&c, "disk", "device");
    layout = value(&c, "disk", "layout");
    if (!!image == !!device || !layout || strcmp(layout, "gpt-ext4")) {
        rc = 2; goto done;
    }
    p.block = device != NULL;
    p.image = realpath(p.block ? device : image, NULL);
    if (!p.image) { perror("holyinstall: disk path"); rc = 6; goto done; }
    if (p.block && strncmp(p.image, "/dev/", 5)) { rc = 2; goto done; }
    fd = open(p.image, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !(p.block ? block_facts(fd, &p) : image_facts(fd, &p))) {
        fputs(p.block ? "holyinstall: device requires 512-byte sectors, a serial and at least 1 GiB\n" :
              "holyinstall: image must be a regular file of at least 1 GiB\n", stderr);
        if (fd >= 0) close(fd);
        rc = 6; goto done;
    }
    close(fd);
    if (!p.block && loop_status(p.image)) {
        fputs("holyinstall: image is attached to a loop device or losetup is unavailable\n", stderr);
        rc = 6; goto done;
    }
    if (p.block) {
        size_t i;
        for (i = 0; i < 4; ++i)
            if (!tool_hash(block_tools[i], p.tools[i])) {
                fprintf(stderr, "holyinstall: missing tool %s\n", block_tools[i]);
                rc = 6; goto done;
            }
    }
    printf("disk %s %s\nidentity %" PRIuMAX ":%" PRIuMAX " size %" PRIuMAX
           "\nGPT: BIOS 2048+2048; ESP %d+%d FAT32; root %d+%" PRIuMAX
           " ext4\nall existing data on this %s will be destroyed\n",
           p.block ? "device" : "image", p.image, p.device, p.inode, p.size, esp_start, esp_sectors,
           root_start, p.root_sectors, p.block ? "device" : "image");
    if (p.block) printf("serial %s\nrdev %" PRIuMAX "\n", p.serial, p.rdev);
    rc = write_plan(plan_path, &p);
done:
    free(p.image); holy_config_free(&c);
    return rc;
}

static int disk_show(const char *plan_path)
{
    struct disk_plan p = {0};
    int rc = read_plan(plan_path, &p);
    if (!rc)
        printf("disk %s %s\nidentity %" PRIuMAX ":%" PRIuMAX
               " size %" PRIuMAX "\nGPT: BIOS 2048+2048; ESP %d+%d FAT32; "
               "root %d+%" PRIuMAX " ext4\nhead-sha256 %s\n"
               "tail-sha256 %s\nall existing data on this %s will be destroyed\n",
               p.block ? "device" : "image", p.image, p.device, p.inode,
               p.size, esp_start, esp_sectors, root_start, p.root_sectors,
               p.head, p.tail, p.block ? "device" : "image");
    if (!rc && p.block) {
        size_t i;
        printf("serial %s\nrdev %" PRIuMAX "\n", p.serial, p.rdev);
        for (i = 0; i < 4; ++i)
            printf("%s %s\n", block_tool_keys[i], p.tools[i]);
    }
    free(p.image);
    return rc;
}

static char *partition_path(const char *disk, unsigned index)
{
    size_t length = strlen(disk);
    int suffix = length && disk[length - 1] >= '0' && disk[length - 1] <= '9';
    char *path = malloc(length + (size_t)suffix + 2);
    if (path) snprintf(path, length + (size_t)suffix + 2, "%s%s%u",
                       disk, suffix ? "p" : "", index);
    return path;
}

static int sysfs_number(const char *directory, const char *name, uintmax_t *number_out)
{
    char *path;
    FILE *input;
    char text[64];
    size_t length = strlen(directory) + strlen(name) + 2;
    int ok;
    path = malloc(length);
    if (!path) return 0;
    snprintf(path, length, "%s/%s", directory, name);
    input = fopen(path, "r");
    free(path);
    if (!input) return 0;
    ok = fgets(text, sizeof text, input) &&
         (strchr(text, '\n') || feof(input));
    fclose(input);
    if (!ok) return 0;
    text[strcspn(text, "\r\n")] = 0;
    return number(text, number_out);
}

static int partition_matches(const char *path, dev_t disk_device,
                             unsigned index, uintmax_t start, uintmax_t sectors)
{
    struct stat st;
    char disk_link[128], part_link[128], *disk_sys, *part_sys, *slash;
    uintmax_t actual_index, actual_start, actual_sectors;
    int n, ok = 0;
    if (stat(path, &st) || !S_ISBLK(st.st_mode)) return 0;
    n = snprintf(disk_link, sizeof disk_link, "/sys/dev/block/%u:%u",
                 major(disk_device), minor(disk_device));
    if (n < 0 || (size_t)n >= sizeof disk_link) return 0;
    n = snprintf(part_link, sizeof part_link, "/sys/dev/block/%u:%u",
                 major(st.st_rdev), minor(st.st_rdev));
    if (n < 0 || (size_t)n >= sizeof part_link) return 0;
    disk_sys = realpath(disk_link, NULL);
    part_sys = realpath(part_link, NULL);
    if (!disk_sys || !part_sys) goto done;
    ok = sysfs_number(part_sys, "partition", &actual_index) &&
         sysfs_number(part_sys, "start", &actual_start) &&
         sysfs_number(part_sys, "size", &actual_sectors) &&
         actual_index == index && actual_start == start &&
         actual_sectors == sectors;
    slash = strrchr(part_sys, '/');
    if (!slash) ok = 0;
    else { *slash = 0; if (strcmp(part_sys, disk_sys)) ok = 0; }
done:
    free(disk_sys); free(part_sys);
    return ok;
}

static int wait_partition(const char *path, dev_t disk_device,
                          unsigned index, uintmax_t start, uintmax_t sectors)
{
    const struct timespec delay = {0, 100000000};
    unsigned attempt;
    for (attempt = 0; attempt < 300; ++attempt) {
        if (partition_matches(path, disk_device, index, start, sectors)) return 1;
        nanosleep(&delay, NULL);
    }
    return 0;
}

static int disk_apply_block(const char *plan_path, const char *confirm,
                            const struct disk_plan *expected)
{
    struct disk_plan actual = {0};
    char *journal_path = NULL, *script = NULL, *esp = NULL, *root = NULL;
    int fd = -1, rc = 1, n;
    size_t i;
    char *const partition[] = {"sfdisk", "--no-reread", "--no-tell-kernel", "/proc/self/fd/9", NULL};
    char *const verify[] = {"sfdisk", "--verify", "/proc/self/fd/9", NULL};
    char *fat[] = {"mkfs.fat", "-F", "32", "-s", "4", "-n", "HOLYBOOT", NULL, NULL};
    char *ext[] = {"mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", NULL, NULL};
    char *const boot[] = {"limine", "bios-install", "/proc/self/fd/9", "1", NULL};
    if (strcmp(confirm, expected->image)) {
        fputs("holyinstall: confirmation must match device path\n", stderr);
        return 3;
    }
    fd = open(expected->image, O_RDWR | O_EXCL | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) || !block_facts(fd, &actual)) {
        fputs("holyinstall: device is busy, changed or unavailable\n", stderr);
        rc = 6; goto done;
    }
    if (actual.device != expected->device || actual.inode != expected->inode ||
        actual.rdev != expected->rdev || actual.size != expected->size ||
        strcmp(actual.serial, expected->serial) ||
        strcmp(actual.head, expected->head) || strcmp(actual.tail, expected->tail)) {
        fputs("holyinstall: device changed since plan\n", stderr);
        rc = 3; goto done;
    }
    for (i = 0; i < 4; ++i) {
        char hash[65];
        if (!tool_hash(block_tools[i], hash) || strcmp(hash, expected->tools[i])) {
            fprintf(stderr, "holyinstall: tool changed since plan: %s\n", block_tools[i]);
            rc = 3; goto done;
        }
    }
    journal_path = malloc(strlen(plan_path) + 9);
    if (!journal_path) goto done;
    sprintf(journal_path, "%s.journal", plan_path);
    if (!access(journal_path, F_OK)) {
        fputs("holyinstall: disk journal exists; inspect before recovery\n", stderr);
        rc = 5; goto done;
    }
    esp = partition_path(expected->image, 2);
    root = partition_path(expected->image, 3);
    if (!esp || !root) goto done;
    fat[7] = esp;
    ext[7] = root;
    n = snprintf(NULL, 0,
        "label: gpt\nunit: sectors\nfirst-lba: 2048\n"
        "start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649\n"
        "start=4096, size=524288, type=U\n"
        "start=528384, size=%" PRIuMAX ", type=L\n", expected->root_sectors);
    if (n < 0) goto done;
    script = malloc((size_t)n + 1);
    if (!script) goto done;
    snprintf(script, (size_t)n + 1,
        "label: gpt\nunit: sectors\nfirst-lba: 2048\n"
        "start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649\n"
        "start=4096, size=524288, type=U\n"
        "start=528384, size=%" PRIuMAX ", type=L\n", expected->root_sectors);
    if (!journal(journal_path, "prepared", 1)) goto done;
    rc = 5;
    if (!journal(journal_path, "partitioning", 0) ||
        child(block_tools[0], partition, script, fd) ||
        fsync(fd) || ioctl(fd, BLKRRPART) ||
        child(block_tools[0], verify, NULL, fd) ||
        !wait_partition(esp, (dev_t)expected->rdev, 2, esp_start, esp_sectors) ||
        !wait_partition(root, (dev_t)expected->rdev, 3, root_start, expected->root_sectors) ||
        !journal(journal_path, "partitioned", 0)) goto done;
    close(fd);
    fd = -1;
    if (!journal(journal_path, "formatting-esp", 0) ||
        child(block_tools[1], fat, NULL, -1) ||
        !journal(journal_path, "formatted-esp", 0) ||
        !journal(journal_path, "formatting-root", 0) ||
        child(block_tools[2], ext, NULL, -1) ||
        !journal(journal_path, "formatted-root", 0)) goto done;
    fd = open(expected->image, O_RDWR | O_EXCL | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !journal(journal_path, "installing-bios", 0) ||
        child(block_tools[3], boot, NULL, fd) || fsync(fd) ||
        !journal(journal_path, "committed", 0)) goto done;
    puts("block device prepared with GPT, FAT32, ext4 and Limine BIOS stage");
    rc = 0;
done:
    if (rc == 5) fputs("holyinstall: device mutation may be partial; inspect journal and device\n", stderr);
    if (fd >= 0) close(fd);
    free(journal_path); free(script); free(esp); free(root);
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
    if (p.block) { rc = disk_apply_block(plan_path, confirm, &p); goto done; }
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

struct final_file {
    char *path;
    uintmax_t device, inode, size;
    char digest[65];
};

struct final_plan {
    struct final_file disk, esp, root, limine;
    uintmax_t root_sectors;
};

static int digest_text(const char *s)
{
    size_t i;
    if (!s || strlen(s) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

static void final_free(struct final_plan *p)
{
    free(p->disk.path); free(p->esp.path); free(p->root.path);
    free(p->limine.path);
}

static int final_facts(int fd, struct final_file *f)
{
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) return 0;
    f->device = (uintmax_t)st.st_dev;
    f->inode = (uintmax_t)st.st_ino;
    f->size = (uintmax_t)st.st_size;
    return hash_span(fd, 0, f->size, f->digest);
}

static int final_open(const char *path, struct final_file *f)
{
    int fd;
    f->path = realpath(path, NULL);
    if (!f->path) return -1;
    fd = open(f->path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !final_facts(fd, f)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int final_entry(FILE *out, const char *name, const struct final_file *f)
{
    return fprintf(out, "%s ", name) >= 0 && quote(out, f->path) &&
        fprintf(out, "\n%s-device %" PRIuMAX "\n%s-inode %" PRIuMAX
                "\n%s-size %" PRIuMAX "\n%s-sha256 %s\n",
                name, f->device, name, f->inode, name, f->size,
                name, f->digest) >= 0;
}

static int final_write(const char *path, const struct final_plan *p)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *out;
    int ok;
    if (fd < 0) { perror("holyinstall: final plan"); return 1; }
    out = fdopen(fd, "w");
    if (!out) { close(fd); unlink(path); return 1; }
    ok = fputs("[disk-finalize-plan]\nformat 1\n", out) >= 0 &&
         final_entry(out, "disk", &p->disk) && final_entry(out, "esp", &p->esp) &&
         final_entry(out, "root", &p->root) && final_entry(out, "limine", &p->limine) &&
         fprintf(out, "root-sectors %" PRIuMAX "\n", p->root_sectors) >= 0;
    if (fflush(out) || fsync(fd)) ok = 0;
    if (fclose(out)) ok = 0;
    if (ok) ok = sync_parent(path);
    if (!ok) { unlink(path); return 1; }
    return 0;
}

static int final_read_file(const struct holy_config *c, const char *name,
                           struct final_file *f)
{
    const char *s;
    char key[64];
    snprintf(key, sizeof key, "%s", name);
    s = value(c, "disk-finalize-plan", key);
    if (!s || s[0] != '/') return 0;
    f->path = strdup(s);
    if (!f->path) return 0;
    snprintf(key, sizeof key, "%s-device", name);
    if (!number(value(c, "disk-finalize-plan", key), &f->device)) return 0;
    snprintf(key, sizeof key, "%s-inode", name);
    if (!number(value(c, "disk-finalize-plan", key), &f->inode)) return 0;
    snprintf(key, sizeof key, "%s-size", name);
    if (!number(value(c, "disk-finalize-plan", key), &f->size)) return 0;
    snprintf(key, sizeof key, "%s-sha256", name);
    s = value(c, "disk-finalize-plan", key);
    if (!digest_text(s)) return 0;
    memcpy(f->digest, s, 65);
    return 1;
}

static int final_read(const char *path, struct final_plan *p)
{
    struct holy_config c = {0};
    char *error = NULL;
    const char *s;
    size_t i;
    int ok = holy_config_load_plan(path, &c, &error);
    if (!ok) { fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid plan"); free(error); return 2; }
    ok = c.count == 22;
    for (i = 0; i < c.count; ++i)
        if (strcmp(c.entries[i].section, "disk-finalize-plan")) ok = 0;
    s = value(&c, "disk-finalize-plan", "format");
    ok = ok && s && !strcmp(s, "1") &&
         final_read_file(&c, "disk", &p->disk) &&
         final_read_file(&c, "esp", &p->esp) &&
         final_read_file(&c, "root", &p->root) &&
         final_read_file(&c, "limine", &p->limine) &&
         number(value(&c, "disk-finalize-plan", "root-sectors"), &p->root_sectors);
    if (ok) ok = p->disk.size >= (1ULL << 30) && p->disk.size % sector == 0 &&
        p->root_sectors == ((p->disk.size / sector - root_start - 34) / 2048) * 2048 &&
        p->esp.size == (uintmax_t)esp_sectors * sector &&
        p->root.size == p->root_sectors * sector &&
        p->limine.size > 0 && !strcmp(p->limine.path, "/usr/bin/limine");
    holy_config_free(&c);
    if (!ok) { fputs("holyinstall: invalid disk finalize plan\n", stderr); return 2; }
    return 0;
}

static int final_match(int fd, const struct final_file *expected)
{
    struct final_file actual = {0};
    return final_facts(fd, &actual) && actual.device == expected->device &&
        actual.inode == expected->inode && actual.size == expected->size &&
        !strcmp(actual.digest, expected->digest);
}

static int final_copy(int source, int target, uintmax_t offset, uintmax_t size)
{
    unsigned char buffer[1048576];
    uintmax_t pos = 0;
    while (pos < size) {
        size_t want = size - pos < sizeof buffer ? (size_t)(size - pos) : sizeof buffer;
        ssize_t got = pread(source, buffer, want, (off_t)pos);
        size_t used = 0;
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return 0;
        while (used < (size_t)got) {
            ssize_t n = pwrite(target, buffer + used, (size_t)got - used,
                               (off_t)(offset + pos + used));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return 0;
            used += (size_t)n;
        }
        pos += (uintmax_t)got;
    }
    return 1;
}

static uint64_t little64(const unsigned char *p)
{
    unsigned i;
    uint64_t value = 0;
    for (i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static int final_layout(int fd, uintmax_t root_sectors)
{
    unsigned char header[512], entries[384];
    uint64_t start[3] = {2048, esp_start, root_start};
    uint64_t count[3] = {2048, esp_sectors, root_sectors};
    size_t i;
    if (pread(fd, header, sizeof header, sector) != (ssize_t)sizeof header ||
        memcmp(header, "EFI PART", 8) || little64(header + 72) != 2 ||
        header[84] != 128 || header[85] || header[86] || header[87] ||
        pread(fd, entries, sizeof entries, sector * 2) != (ssize_t)sizeof entries) return 0;
    for (i = 0; i < 3; ++i)
        if (little64(entries + i * 128 + 32) != start[i] ||
            little64(entries + i * 128 + 40) != start[i] + count[i] - 1) return 0;
    return 1;
}

static int final_plan_make(const char *disk_plan_path, const char *esp,
                           const char *root, const char *output)
{
    struct disk_plan base = {0}, actual = {0};
    struct final_plan p = {0};
    char *journal_path = NULL;
    FILE *journal_file = NULL;
    char last[64] = {0}, line[64];
    int fd = -1, rc = read_plan(disk_plan_path, &base);
    char *const verify[] = {"sfdisk", "--verify", "/proc/self/fd/9", NULL};
    if (rc) goto done;
    journal_path = malloc(strlen(disk_plan_path) + 9);
    if (!journal_path) { rc = 1; goto done; }
    sprintf(journal_path, "%s.journal", disk_plan_path);
    {
        struct stat st;
        int journal_fd = open(journal_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (journal_fd < 0) { rc = 6; goto done; }
        if (fstat(journal_fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 4096) {
            close(journal_fd); rc = 2; goto done;
        }
        journal_file = fdopen(journal_fd, "r");
        if (!journal_file) { close(journal_fd); rc = 1; goto done; }
    }
    while (fgets(line, sizeof line, journal_file)) {
        if (!strchr(line, '\n')) { rc = 2; goto done; }
        memcpy(last, line, strlen(line) + 1);
    }
    if (strcmp(last, "committed\n")) { rc = 5; goto done; }
    fd = open(base.image, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !image_facts(fd, &actual) ||
        actual.device != base.device || actual.inode != base.inode ||
        actual.size != base.size || actual.root_sectors != base.root_sectors ||
        loop_status(base.image) || !final_layout(fd, base.root_sectors) ||
        child("/usr/sbin/sfdisk", verify, NULL, fd)) {
        rc = 6; goto done;
    }
    p.root_sectors = base.root_sectors;
    if (final_open(base.image, &p.disk) || final_open(esp, &p.esp) ||
        final_open(root, &p.root) || final_open("/usr/bin/limine", &p.limine)) {
        rc = 6; goto done;
    }
    if (p.esp.size != (uintmax_t)esp_sectors * sector ||
        p.root.size != p.root_sectors * sector) { rc = 2; goto done; }
    printf("disk %s\nesp %s sha256 %s\nroot %s sha256 %s\nlimine %s sha256 %s\n",
           p.disk.path, p.esp.path, p.esp.digest, p.root.path, p.root.digest,
           p.limine.path, p.limine.digest);
    rc = final_write(output, &p);
done:
    if (journal_file) fclose(journal_file);
    if (fd >= 0) close(fd);
    free(journal_path); free(base.image); final_free(&p);
    return rc;
}

static int final_apply(const char *path, const char *confirm)
{
    struct final_plan p = {0};
    int disk = -1, esp = -1, root = -1, limine = -1;
    int rc = final_read(path, &p);
    char *journal_path = NULL;
    char check[65];
    char *const install[] = {"limine", "bios-install", "/proc/self/fd/9", "1", NULL};
    char *const verify[] = {"sfdisk", "--verify", "/proc/self/fd/9", NULL};
    if (rc) goto done;
    if (strcmp(confirm, p.disk.path)) { rc = 3; goto done; }
    disk = open(p.disk.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    esp = open(p.esp.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    root = open(p.root.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    limine = open(p.limine.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (disk < 0 || esp < 0 || root < 0 || limine < 0 ||
        flock(disk, LOCK_EX | LOCK_NB)) { rc = 6; goto done; }
    if (!final_match(disk, &p.disk) || !final_match(esp, &p.esp) ||
        !final_match(root, &p.root) || !final_match(limine, &p.limine)) {
        fputs("holyinstall: disk or source image changed since plan\n", stderr);
        rc = 3; goto done;
    }
    if (loop_status(p.disk.path)) { rc = 6; goto done; }
    if (access("/usr/sbin/sfdisk", X_OK) || access(p.limine.path, X_OK)) {
        fputs("holyinstall: sfdisk and Limine are required\n", stderr);
        rc = 6; goto done;
    }
    journal_path = malloc(strlen(path) + 9);
    if (!journal_path) { rc = 1; goto done; }
    sprintf(journal_path, "%s.journal", path);
    if (!journal(journal_path, "prepared", 1)) { rc = errno == EEXIST ? 5 : 1; goto done; }
    rc = 5;
    if (!journal(journal_path, "copying-esp", 0) ||
        !final_copy(esp, disk, (uintmax_t)esp_start * sector, p.esp.size) ||
        fsync(disk) || !hash_span(disk, (uintmax_t)esp_start * sector, p.esp.size, check) ||
        strcmp(check, p.esp.digest) || !journal(journal_path, "copied-esp", 0)) goto done;
    if (!journal(journal_path, "copying-root", 0) ||
        !final_copy(root, disk, (uintmax_t)root_start * sector, p.root.size) ||
        fsync(disk) || !hash_span(disk, (uintmax_t)root_start * sector, p.root.size, check) ||
        strcmp(check, p.root.digest) || !journal(journal_path, "copied-root", 0)) goto done;
    if (!journal(journal_path, "installing-limine", 0) ||
        child("/usr/bin/limine", install, NULL, disk) ||
        child("/usr/sbin/sfdisk", verify, NULL, disk) || fsync(disk) ||
        !journal(journal_path, "committed", 0)) goto done;
    puts("disk image finalized");
    rc = 0;
done:
    if (rc == 5) fputs("holyinstall: disk finalize may be partial; inspect journal and image\n", stderr);
    if (disk >= 0) close(disk);
    if (esp >= 0) close(esp);
    if (root >= 0) close(root);
    if (limine >= 0) close(limine);
    free(journal_path); final_free(&p);
    return rc;
}

int holy_disk_main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[0], "show") && !strcmp(argv[1], "--plan"))
        return disk_show(argv[2]);
    if (argc == 9 && !strcmp(argv[0], "finalize-plan") &&
        !strcmp(argv[1], "--disk-plan") && !strcmp(argv[3], "--esp") &&
        !strcmp(argv[5], "--root-image") && !strcmp(argv[7], "--output"))
        return final_plan_make(argv[2], argv[4], argv[6], argv[8]);
    if (argc == 5 && !strcmp(argv[0], "finalize-apply") &&
        !strcmp(argv[1], "--plan") && !strcmp(argv[3], "--confirm"))
        return final_apply(argv[2], argv[4]);
    if (argc == 5 && !strcmp(argv[0], "plan") &&
        !strcmp(argv[1], "--config") && !strcmp(argv[3], "--output"))
        return disk_plan(argv[2], argv[4]);
    if (argc == 5 && !strcmp(argv[0], "apply") &&
        !strcmp(argv[1], "--plan") && !strcmp(argv[3], "--confirm"))
        return disk_apply(argv[2], argv[4]);
    fputs("usage: holyinstall disk show --plan PLAN | "
          "holyinstall disk plan --config FILE --output NEW_PLAN | "
          "holyinstall disk apply --plan PLAN --confirm IMAGE | "
          "holyinstall disk finalize-plan --disk-plan PLAN --esp FILE "
          "--root-image FILE --output NEW_PLAN | "
          "holyinstall disk finalize-apply --plan PLAN --confirm IMAGE\n", stderr);
    return 2;
}
