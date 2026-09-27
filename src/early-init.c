#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void fail(const char *what)
{
    perror(what);
    for (;;) pause();
}

int main(void)
{
    FILE *input;
    char *line = NULL, *word;
    size_t capacity = 0;
    int console, fd;
    char *service = "boot";
    char *args[] = { "/sbin/init", "--services-dir", "/etc/dinit.d",
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
    for (word = strtok(line, " \t\r\n"); word; word = strtok(NULL, " \t\r\n"))
        if (!strcmp(word, "holy.test=1")) service = "holy-test";
    free(line);
    args[6] = service;
    execv(args[0], args);
    fail("holy-init: exec dinit");
    return 1;
}
