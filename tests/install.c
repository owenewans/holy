#define _POSIX_C_SOURCE 200809L
#include "install.h"
#include "verify.h"

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int root, ok;
    if (argc != 3 || !holy_verify_with_output(argv[1], 0)) return 2;
    root = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return 2;
    ok = holy_install_preflight(argv[1], root) &&
         holy_install_payload(argv[1], root);
    close(root);
    return ok ? 0 : 4;
}
