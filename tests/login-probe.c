#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int attempt(const char *password, int expect_success)
{
    char output[16384] = {0};
    size_t used = 0;
    const char *slave;
    int master, status = 0, sent = 0, doas_sent = 0, found = 0, root_found = 0;
    pid_t child;
    time_t deadline;
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) || unlockpt(master) ||
        !(slave = ptsname(master))) return 1;
    child = fork();
    if (child < 0) return 1;
    if (!child) {
        int terminal;
        if (setsid() < 0) _exit(1);
        terminal = open(slave, O_RDWR);
        if (terminal < 0 || ioctl(terminal, TIOCSCTTY, 0) ||
            dup2(terminal, STDIN_FILENO) < 0 ||
            dup2(terminal, STDOUT_FILENO) < 0 ||
            dup2(terminal, STDERR_FILENO) < 0) _exit(1);
        if (terminal > STDERR_FILENO) close(terminal);
        close(master);
        execl("/usr/bin/login", "login", "holytest", (char *)NULL);
        _exit(127);
    }
    deadline = time(NULL) + 30;
    while (time(NULL) < deadline) {
        struct pollfd fd = { master, POLLIN, 0 };
        ssize_t got;
        if (poll(&fd, 1, 500) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!(fd.revents & POLLIN)) {
            if (waitpid(child, &status, WNOHANG) == child) goto finished;
            continue;
        }
        if (used >= sizeof output - 1) break;
        got = read(master, output + used, sizeof output - used - 1);
        if (got <= 0) break;
        used += (size_t)got;
        output[used] = 0;
        if (!sent && strstr(output, "Password:")) {
            size_t length = strlen(password);
            if (write(master, password, length) != (ssize_t)length)
                break;
            sent = 1;
        }
        if (!expect_success && sent && strstr(output, "Login incorrect")) {
            kill(-child, SIGKILL);
            waitpid(child, &status, 0);
            close(master);
            return 0;
        }
        if (strstr(output, "HOLY-LOGIN-UID 10001")) found = 1;
        if (expect_success && found && !doas_sent && strstr(output, "doas (") &&
            strstr(output, "password: ")) {
            static const char response[] = "holytestpass\n";
            if (write(master, response, sizeof response - 1) != sizeof response - 1)
                break;
            doas_sent = 1;
        }
        if (strstr(output, "HOLY-DOAS-UID 0")) root_found = 1;
        if (found && root_found && waitpid(child, &status, WNOHANG) == child) goto finished;
    }
    kill(-child, SIGKILL);
    waitpid(child, &status, 0);
    close(master);
    fputs("login probe timed out or failed\n", stderr);
    return 1;
finished:
    close(master);
    if (!expect_success || !sent || !doas_sent || !found || !root_found ||
        !WIFEXITED(status) || WEXITSTATUS(status)) {
        fputs("login authentication or uid check failed\n", stderr);
        fputs(output, stderr);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (attempt("wrong-fixture-password\n", 0) ||
        attempt("holytestpass\n", 1)) return 1;
    puts("login rejected wrong password and authenticated uid=10001; doas authenticated uid=0");
    return 0;
}
