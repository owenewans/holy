#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void *worker(void *value) { return value; }

int main(int argc, char **argv)
{
    pthread_t thread;
    struct timespec now;
    void *value = malloc(64), *result;
    char input[32];
    if (!value || clock_gettime(CLOCK_MONOTONIC, &now) ||
        pthread_create(&thread, NULL, worker, value) ||
        pthread_join(thread, &result) || result != value) return 1;
    free(value);
    if (argc == 2) {
        if (!fgets(input, sizeof input, stdin) ||
            input[strcspn(input, "\n")] != '\n') return 1;
        input[strcspn(input, "\n")] = '\0';
        if (strcmp(input, argv[1])) return 1;
    } else if (argc != 1) return 2;
    return puts(HOLY_LIBC "-probe") < 0;
}
