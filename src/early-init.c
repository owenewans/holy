#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *what)
{
    perror(what);
    for (;;) pause();
}

static void wait_device(const char *device)
{
    const struct timespec delay = {0, 100000000};
    struct stat st;
    unsigned int attempt;
    if (strncmp(device, "/dev/", 5) || !device[5]) {
        errno = EINVAL;
        fail("holy-init: root requires a /dev block device");
    }
    for (attempt = 0; attempt < 300; ++attempt) {
        if (!stat(device, &st)) break;
        if (errno != ENOENT) fail("holy-init: root device");
        nanosleep(&delay, NULL);
    }
    if (attempt == 300) { errno = ETIMEDOUT; fail("holy-init: root device"); }
    if (!S_ISBLK(st.st_mode)) { errno = ENOTBLK; fail("holy-init: root device"); }
}

static void mount_disk(const char *device, const char *esp)
{
    static const char *const mounts[] = { "/dev", "/proc", "/sys", "/run", "/tmp" };
    struct stat st;
    size_t i;
    wait_device(device);
    if (mkdir("/newroot", 0755) || mount(device, "/newroot", "ext4", 0, NULL))
        fail("holy-init: mount ext4 root");
    if (access("/newroot/sbin/init", X_OK)) fail("holy-init: missing disk init");
    if (esp) {
        wait_device(esp);
        if (lstat("/newroot/boot", &st)) fail("holy-init: boot directory");
        if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; fail("holy-init: boot directory"); }
        if (mount(esp, "/newroot/boot", "vfat", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  "uid=0,gid=0,fmask=0133,dmask=0022"))
            fail("holy-init: mount FAT ESP");
    }
    for (i = 0; i < sizeof mounts / sizeof *mounts; ++i) {
        char destination[32];
        int size = snprintf(destination, sizeof destination, "/newroot%s", mounts[i]);
        if (size < 0 || (size_t)size >= sizeof destination ||
            mount(mounts[i], destination, NULL, MS_MOVE, NULL))
            fail("holy-init: move runtime mount");
    }
}

int main(void)
{
    FILE *input;
    char *line = NULL, *word, *device = NULL, *esp = NULL;
    size_t capacity = 0;
    int console, fd;
    char *service = "boot";
    char *args[] = { "/sbin/init", "--services-dir", "/etc/dinit.d",
                     "--socket-path", "/run/dinitctl", "--service", NULL, NULL };
    char *disk_args[] = { "/usr/bin/busybox", "switch_root", "/newroot",
                         "/sbin/init", "--services-dir", "/etc/dinit.d",
                         "--socket-path", "/run/dinitctl", "--service", NULL, NULL };
    if (getpid() != 1) {
        fputs("holy-init: requires PID 1\n", stderr);
        return 2;
    }
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755"))
        fail("holy-init: devtmpfs");
    console = open("/dev/console", O_RDWR);
    if (console < 0) fail("holy-init: console");
    for (fd = 0; fd < 3; ++fd)
        if (dup2(console, fd) < 0) fail("holy-init: console descriptor");
    if (console > 2) close(console);
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
        fail("holy-init: private mounts");
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
        mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777"))
        fail("holy-init: runtime mounts");
    if (mkdir("/dev/pts", 0755) ||
        mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=0620"))
        fail("holy-init: devpts");
    if (setenv("PATH", "/usr/bin", 1) || setenv("HOME", "/root", 1))
        fail("holy-init: environment");
    input = fopen("/proc/cmdline", "r");
    if (!input || getline(&line, &capacity, input) < 0)
        fail("holy-init: kernel command line");
    fclose(input);
    for (word = strtok(line, " \t\r\n"); word; word = strtok(NULL, " \t\r\n")) {
        if (!strcmp(word, "holy.test=1")) service = "holy-test";
        if (!strncmp(word, "holy.root=", 10)) {
            if (device || !word[10]) { errno = EINVAL; fail("holy-init: duplicate or empty root"); }
            device = strdup(word + 10);
            if (!device) fail("holy-init: root allocation");
        }
        if (!strncmp(word, "holy.esp=", 9)) {
            if (esp || !word[9]) { errno = EINVAL; fail("holy-init: duplicate or empty ESP"); }
            esp = strdup(word + 9);
            if (!esp) fail("holy-init: ESP allocation");
        }
        if (!strncmp(word, "holy.rootfstype=", 16) && strcmp(word + 16, "ext4")) {
            errno = ENOTSUP;
            fail("holy-init: only ext4 disk roots supported");
        }
    }
    free(line);
    if (esp && !device) { errno = EINVAL; fail("holy-init: ESP requires disk root"); }
    if (device) {
        mount_disk(device, esp);
        free(device);
        free(esp);
        disk_args[9] = service;
        execv(disk_args[0], disk_args);
        fail("holy-init: switch_root");
    }
    args[6] = service;
    execv(args[0], args);
    fail("holy-init: exec dinit");
    return 1;
}
