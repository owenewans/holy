#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share" "$tree"
db="$root/var/lib/holypkg"
expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
package() {
    name=$1 path=$2 dependency=$3
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "${4:-$name}" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$name" > "$tree/DATA/usr/share/$path"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
"$bin" db init --root "$root" > "$tmp/out"
package app app lib
package lib lib ''
package unused unused ''
app=$(hash app) lib=$(hash lib) unused=$(hash unused)
package alternative alternative '' lib
alternative=$(hash alternative)
expect 3 "$bin" db plan-set "$app" "$lib" "$alternative" --root "$root"
expect 0 "$bin" db plan-set "$app" "$lib" "$alternative" --choose "dep-1=$lib" --root "$root"
chosen=$(plan_hash)
expect 3 "$bin" db apply-set "$chosen" "$app" "$lib" --root "$root"
test ! -e "$root/usr/share/app"
expect 4 "$bin" db plan-set "$app" --root "$root"
expect 0 "$bin" db plan-set "$app" "$lib" "$unused" --root "$root"
plan=$(plan_hash)
test "${#plan}" -eq 64
grep -qx "selected $app app explicit" "$tmp/out"
grep -qx "selected $lib lib dependency" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 4
test "$(cat "$db/generation")" -eq 0
test ! -e "$root/usr/share/app"
expect 0 "$bin" db plan-set "$app" "$unused" "$lib" --root "$root"
test "$(plan_hash)" = "$plan"
expect 3 "$bin" db apply-set "$(printf '%064d' 0)" "$app" "$lib" --root "$root"
test ! -e "$db/transactions/set-journal"
test ! -e "$root/usr/share/app"
printf '2\n' > "$db/generation"
expect 3 "$bin" db apply-set "$plan" "$app" "$lib" "$unused" --root "$root"
test ! -e "$root/usr/share/app"
printf '0\n' > "$db/generation"
expect 0 "$bin" db apply-set "$plan" "$app" "$lib" "$unused" --root "$root"
grep -qx "committed-set $plan generation 1 artifacts 2" "$tmp/out"
test "$(cat "$db/generation")" -eq 1
grep -qx app "$root/usr/share/app"
grep -qx lib "$root/usr/share/lib"
test ! -e "$root/usr/share/unused"
grep -qx 'reason explicit' "$db/installed/$app/state"
grep -qx 'reason dependency' "$db/installed/$lib/state"
cmp "$db/installed/$app/graph" "$db/installed/$lib/graph"
grep -Fqx "edge \"$app\" \"dep-1\" \"$lib\" \"-\" \"package\" \"lib\"" "$db/installed/$app/graph"
expect 0 "$bin" db status --root "$root"
expect 0 "$bin" db check --all --root "$root"
expect 3 "$bin" db rm "$lib" --root "$root"
test -f "$root/usr/share/lib"
test "$(cat "$db/generation")" -eq 1
journal() {
    printf 'format holy-set-journal-1\ngeneration 0\nplan %s\nroot %s\nchoice -\n' "$plan" "$app"
    printf '%s\n' "$app" "$lib" | sort | sed 's/^/artifact /'
}
journal > "$db/transactions/set-journal"
chmod 600 "$db/transactions/set-journal"
expect 5 "$bin" db status --root "$root"
cp "$db/installed/$lib/files" "$tmp/installed-files"
: > "$db/installed/$lib/files"
expect 5 "$bin" db recover --finish-set --root "$root"
mv "$tmp/installed-files" "$db/installed/$lib/files"
printf broken > "$root/usr/share/lib"
expect 5 "$bin" db recover --finish-set --root "$root"
test -f "$db/transactions/set-journal"
printf 'lib\n' > "$root/usr/share/lib"
expect 0 "$bin" db recover --finish-set --root "$root"
test ! -e "$db/transactions/set-journal"
test "$(cat "$db/generation")" -eq 1
journal > "$db/transactions/set-journal"
chmod 600 "$db/transactions/set-journal"
printf '0\n' > "$db/generation"
expect 0 "$bin" db recover --finish-set --root "$root"
test "$(cat "$db/generation")" -eq 1
expect 0 "$bin" db rm "$app" --root "$root"
expect 0 "$bin" db rm "$lib" --root "$root"
test "$(cat "$db/generation")" -eq 3
package collision app ''
collision=$(hash collision)
# the selected provider also collides with its consumer.
rm "$tmp/app.holy"
package app collision collision
app=$(hash app)
expect 0 "$bin" db plan-set "$app" "$collision" --root "$root"
rm "$tmp/collision.holy"
package collision collision ''
collision=$(hash collision)
expect 4 "$bin" db plan-set "$app" "$collision" --root "$root"
test ! -e "$root/usr/share/collision"
rm "$tmp/app.holy"
package app app lib
app=$(hash app)
expect 0 "$bin" db plan-set "$app" "$lib" --root "$root"
plan=$(plan_hash)
second=$(printf '%s\n' "$app" "$lib" | sort | tail -1)
if test "$second" = "$app"; then target=app; first=$lib; else target=lib; first=$app; fi
cat > "$tmp/fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
int openat(int dir, const char *path, int flags, ...)
{
    static int (*real_openat)(int, const char *, int, ...);
    mode_t mode = 0;
    const char *fail = getenv("HOLY_FAIL_PATH");
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!real_openat) {
        void *symbol = dlsym(RTLD_NEXT, "openat");
        memcpy(&real_openat, &symbol, sizeof real_openat);
        if (!real_openat) abort();
    }
    if ((flags & O_CREAT) && fail && !strcmp(path, fail)) { errno = ENOSPC; return -1; }
    return real_openat(dir, path, flags, mode);
}
C
gcc -shared -fPIC -o "$tmp/fault.so" "$tmp/fault.c" -ldl
expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH="$target" "$bin" db apply-set "$plan" "$app" "$lib" --root "$root"
test -f "$db/transactions/set-journal"
test -f "$db/installed/$first/state"
test ! -e "$db/installed/$second"
test "$(cat "$db/generation")" -eq 3
expect 5 "$bin" db status --root "$root"
expect 5 "$bin" db check --all --root "$root" --json
grep -q '"code":"incomplete-transaction","status":5' "$tmp/out"
expect 5 "$bin" db rm "$first" --root "$root"
expect 5 "$bin" db recover --finish-set --root "$root"
# an unrecorded partial payload requires inspection, not silent overwriting.
printf partial > "$root/usr/share/$target"
expect 5 "$bin" db recover --continue-set --root "$root"
grep -qx partial "$root/usr/share/$target"
rm "$root/usr/share/$target"
expect 0 "$bin" db recover --continue-set --root "$root"
grep -qx "resumed $second" "$tmp/out"
test "$(cat "$db/generation")" -eq 4
expect 0 "$bin" db check --all --root "$root"
test ! -e "$db/transactions/set-journal"
printf 'package set fixtures passed\n'

