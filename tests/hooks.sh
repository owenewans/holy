#!/bin/sh
set -eu
bin=$(realpath "$1")
if test "${HOLY_HOOKS_UNSHARED:-}" != 1; then
    command -v unshare >/dev/null || { echo 'unshare required' >&2; exit 6; }
    unshare -Ur true || { echo 'user namespaces required' >&2; exit 6; }
    exec unshare -Ur env HOLY_HOOKS_UNSHARED=1 sh "$0" "$bin"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/share/holy" "$tmp/root/bin"
cat > "$tmp/runner.c" <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    char text[32];
    int fd, marker;
    ssize_t n;
    if (argc != 2 || (fd = open(argv[1], O_RDONLY)) < 0) return 4;
    n = read(fd, text, sizeof text);
    close(fd);
    if (n < 0) return 4;
    marker = open("/hook-marker", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker >= 0) {
        write(marker, "ran\n", 4);
        close(marker);
        return n == 10 && !memcmp(text, "fail-once\n", 10) ? 1 : 0;
    }
    return errno == EEXIST ? 0 : 4;
}
EOF
${CC:-cc} -static -o "$tmp/root/bin/holy-hook-runner" "$tmp/runner.c"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name hook-fixture
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for name in deps provides origin transform; do : > "$tmp/payload/HOLY/$name"; done
printf 'fail-once\n' > "$tmp/payload/DATA/usr/share/holy/hook.txt"
hash=$(sha256sum "$tmp/payload/DATA/usr/share/holy/hook.txt")
hash=${hash%% *}
printf 'hook postinstall /bin/holy-hook-runner usr/share/holy/hook.txt sha256 %s\n' "$hash" > "$tmp/payload/HOLY/hooks"
uid=$(id -u)
gid=$(id -g)
: > "$tmp/payload/HOLY/files"
for path in usr usr/share usr/share/holy; do
    mode=$(stat -c %a "$tmp/payload/DATA/$path")
    printf 'dir %s %s root root %s %s 0 - none - -\n' "$path" "$mode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
printf 'file usr/share/holy/hook.txt 644 root root %s %s 10 %s none - -\n' "$uid" "$gid" "$hash" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/package.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/package.tar" "$tmp/package.holy"
artifact=$(sha256sum "$tmp/package.holy")
artifact=${artifact%% *}
"$bin" db init --root "$tmp/root" > "$tmp/out"
"$bin" add "local:$tmp/package.holy" --skip-hooks "$artifact" --root "$tmp/root" --yes > "$tmp/out"
"$bin" db configure-plan "$artifact" --root "$tmp/root" > "$tmp/out"
grep -Fqx 'fail-once' "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out" | head -1)
test "${#plan}" -eq 64
printf 'tampered\n' > "$tmp/root/usr/share/holy/hook.txt"
if "$bin" db configure-apply "$plan" "$artifact" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -e "$tmp/root/var/lib/holypkg/transactions/hook-journal"
cp "$tmp/payload/DATA/usr/share/holy/hook.txt" "$tmp/root/usr/share/holy/hook.txt"
cp "$tmp/root/bin/holy-hook-runner" "$tmp/runner-saved"
printf 'changed\n' > "$tmp/root/bin/holy-hook-runner"
if "$bin" db configure-apply "$plan" "$artifact" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
test ! -e "$tmp/root/var/lib/holypkg/transactions/hook-journal"
cp "$tmp/runner-saved" "$tmp/root/bin/holy-hook-runner"
if "$bin" db configure-apply "$(printf '%064d' 0)" "$artifact" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
test ! -e "$tmp/root/hook-marker"
if "$bin" db configure-apply "$plan" "$artifact" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx ran "$tmp/root/hook-marker"
grep -q '^stage running$' "$tmp/root/var/lib/holypkg/transactions/hook-journal"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
"$bin" db configure-recover "$artifact" --retry --root "$tmp/root" > "$tmp/out"
grep -qx "configured $artifact generation 2 hooks 1" "$tmp/out"
test ! -e "$tmp/root/var/lib/holypkg/transactions/hook-journal"
grep -qx "completed sha256 $(sha256sum "$tmp/payload/HOLY/hooks" | cut -d ' ' -f 1)" "$tmp/root/var/lib/holypkg/installed/$artifact/hooks-state"
"$bin" db check "$artifact" --root "$tmp/root" > "$tmp/out"
grep -qx "intact $artifact generation 2" "$tmp/out"
printf 'ok\n' > "$tmp/payload/DATA/usr/share/holy/hook.txt"
hash=$(sha256sum "$tmp/payload/DATA/usr/share/holy/hook.txt")
hash=${hash%% *}
printf 'hook postinstall /bin/holy-hook-runner usr/share/holy/hook.txt sha256 %s\n' "$hash" > "$tmp/payload/HOLY/hooks"
printf 'file usr/share/holy/hook.txt 644 root root %s %s 3 %s none - -\n' "$uid" "$gid" "$hash" > "$tmp/payload/HOLY/files-new"
sed -n '1,3p' "$tmp/payload/HOLY/files" > "$tmp/dirs"
cat "$tmp/dirs" "$tmp/payload/HOLY/files-new" > "$tmp/payload/HOLY/files"
rm "$tmp/payload/HOLY/files-new"
mkdir "$tmp/root-success"
mkdir "$tmp/root-success/bin"
cp "$tmp/root/bin/holy-hook-runner" "$tmp/root-success/bin/holy-hook-runner"
tar -cf "$tmp/success.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/success.tar" "$tmp/success.holy"
success=$(sha256sum "$tmp/success.holy")
success=${success%% *}
"$bin" db init --root "$tmp/root-success" > "$tmp/out"
"$bin" add "local:$tmp/success.holy" --skip-hooks "$success" --root "$tmp/root-success" --yes > "$tmp/out"
"$bin" db configure-plan "$success" --root "$tmp/root-success" > "$tmp/out"
success_plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out" | head -1)
"$bin" db configure-apply "$success_plan" "$success" --root "$tmp/root-success" > "$tmp/out"
grep -qx "configured $success generation 2 hooks 1" "$tmp/out"
grep -qx ran "$tmp/root-success/hook-marker"
echo 'native hook fixtures passed'
