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
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "${4:-$name}" "${5:-1}" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf 'source-name forged\n' >> "$tree/HOLY/meta"
    printf 'source-id forged\n' > "$tree/HOLY/origin"
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
register() {
    expect 0 "$bin" source plan --config "$tmp/config" --root "$root"
    cp "$tmp/out" "$tmp/source-plan"
    source_plan=$(sha256sum "$tmp/source-plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/source-plan" --sha256 "$source_plan" --root "$root"
}
cat > "$tmp/config" <<'EOF'
[source first]
type holy-http
url https://first.example/holy
[source second]
type holy-http
url https://second.example/holy
EOF
cp "$tmp/config" "$tmp/active-config"
register
expect 0 "$bin" source list --root "$root"
one=$(sed -n 's/^source \([0-9a-f]*\) "first" active$/\1/p' "$tmp/out")
two=$(sed -n 's/^source \([0-9a-f]*\) "second" active$/\1/p' "$tmp/out")
package app app lib
package lib lib ''
package extra extra lib
package unused unused ''
app=$(hash app) lib=$(hash lib) extra=$(hash extra) unused=$(hash unused)
expect 0 "$bin" db plan-set "$app" "$lib" --root "$root"
local_plan=$(plan_hash)
expect 0 "$bin" db plan-set "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
plan=$(plan_hash)
test "$plan" != "$local_plan"
grep -qx "binding $app source $one \"first\"" "$tmp/out"
expect 0 "$bin" db plan-set "$app" "$lib" --source "$lib=$two" --source "$app=$one" --root "$root"
test "$(plan_hash)" = "$plan"
expect 2 "$bin" db plan-set "$app" "$lib" --source "$app=$one" --source "$app=$two" --root "$root"
expect 3 "$bin" db plan-set "$app" "$lib" "$unused" --source "$unused=$one" --root "$root"
expect 6 "$bin" db plan-set "$app" "$lib" --source "$app=$(printf '%064d' 0)" --root "$root"
expect 3 "$bin" db apply-set "$plan" "$app" "$lib" --root "$root"
expect 3 "$bin" db apply-set "$plan" "$app" "$lib" --source "$app=$two" --source "$lib=$two" --root "$root"
test ! -e "$root/usr/share/app"
sed 's/source first/source renamed/' "$tmp/config" > "$tmp/changed"
mv "$tmp/changed" "$tmp/config"
register
expect 3 "$bin" db apply-set "$plan" "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
expect 0 "$bin" db plan-set "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
grep -qx 'format holy-instance-4' "$db/installed/$app/state"
grep -qx "source-id $one" "$db/installed/$app/state"
grep -qx "source $one \"renamed\"" "$db/installed/$app/source"
grep -qx "source-id $two" "$db/installed/$lib/state"
cp "$db/installed/$lib/state" "$tmp/legacy-source-state"
mv "$db/installed/$lib/provides" "$tmp/legacy-source-provides"
sed '/^provides /d; s/holy-instance-4/holy-instance-3/' "$tmp/legacy-source-state" > "$db/installed/$lib/state"
expect 0 "$bin" db status --root "$root"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" check --root "$root" --json
grep -q '"type":"summary"' "$tmp/out"
expect 0 "$bin" check renamed:app --root "$root"
grep -q "^intact $app generation " "$tmp/out"
expect 0 "$bin" check second:lib --root "$root" --json
grep -q "\"artifact\":\"$lib\"" "$tmp/out"
expect 0 "$bin" files renamed:app --root "$root"
grep -qx '"/usr/share/app"' "$tmp/out"
expect 0 "$bin" owner /usr/share/app --root "$root"
grep -q "$app" "$tmp/out"
expect 0 "$bin" why renamed:app --root "$root"
grep -qx "path 0 $app \"app\" reason=explicit" "$tmp/out"
expect 0 "$bin" why second:lib --root "$root" --json
grep -q "\"type\":\"path\",\"depth\":1,\"artifact\":\"$lib\"" "$tmp/out"
printf 'drift\n' > "$root/usr/share/app"
expect 0 "$bin" files renamed:app --root "$root"
grep -qx '"/usr/share/app"' "$tmp/out"
expect 4 "$bin" check renamed:app --root "$root"
printf 'app\n' > "$root/usr/share/app"
expect 6 "$bin" check second:app --root "$root"
expect 2 "$bin" check renamed:app --root "$root" --arch ''
expect 3 "$bin" rm renamed:app --root "$root"
test -f "$root/usr/share/app"
cp "$tmp/legacy-source-state" "$db/installed/$lib/state"
mv "$tmp/legacy-source-provides" "$db/installed/$lib/provides"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" orphan --root "$root" --json
cp "$db/installed/$lib/state" "$tmp/lib-state"
if test "${HOLY_SOURCE_CHROOT:-0}" = 1; then
    command -v doas >/dev/null && doas -n true || exit 6
    test ! -e "$root/lib" && test ! -e "$root/lib64" && test ! -e "$root/usr/lib"
    mkdir "$root/tmp"
    cp "$bin" "$root/source-client"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client db check --all --root /
    rm "$root/usr/share/lib"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client db repair-plan "$lib" --root /
    repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
    test "${#repair}" -eq 64
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client db repair "$lib" --plan "$repair" --root /
    cmp "$db/installed/$lib/state" "$tmp/lib-state"
fi
printf '[general]\narch x86_64\n' > "$tmp/config"
register
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db plan-set "$extra" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$extra" --root "$root"
cmp "$db/installed/$lib/state" "$tmp/lib-state"
grep -qx 'source-id -' "$db/installed/$extra/state"
test ! -e "$db/installed/$extra/source"
expect 6 "$bin" db plan-set "$unused" --source "$unused=$one" --root "$root"
cp "$db/installed/$app/source" "$tmp/saved-source"
printf corrupt > "$db/installed/$app/source"
expect 1 "$bin" db status --root "$root"
cp "$tmp/saved-source" "$db/installed/$app/source"
cp "$db/installed/$app/state" "$tmp/saved-state"
sed "s/source-id $one/source-id $two/" "$tmp/saved-state" > "$db/installed/$app/state"
expect 1 "$bin" db status --root "$root"
cp "$tmp/saved-state" "$db/installed/$app/state"
printf '\000hidden\n' >> "$db/installed/$app/state"
expect 1 "$bin" db status --root "$root"
cp "$tmp/saved-state" "$db/installed/$app/state"
expect 0 "$bin" db rm "$extra" --root "$root"
expect 0 "$bin" rm renamed:app --root "$root" --yes
expect 0 "$bin" why second:lib --root "$root" --json
grep -q "\"type\":\"orphan\",\"artifact\":\"$lib\"" "$tmp/out"
expect 0 "$bin" rm second:lib --root "$root" --yes
test ! -e "$db/installed/$app"
test ! -e "$db/installed/$lib"
if test "${HOLY_SOURCE_STATIC:-0}" != 1; then
    cp "$tmp/active-config" "$tmp/config"
    register
    expect 0 "$bin" db plan-set "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
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

    expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH="$target" "$bin" db apply-set "$plan" "$app" "$lib" --source "$app=$one" --source "$lib=$two" --root "$root"
    grep -qx 'format holy-set-journal-2' "$db/transactions/set-journal"
    test -f "$db/installed/$first/source"
    test ! -e "$db/installed/$second"
    cp "$db/transactions/set-journal" "$tmp/interrupted-journal"
    expect 5 "$bin" source plan --config "$tmp/config" --root "$root"
    expect 5 "$bin" db recover --finish-set --root "$root"
    cp "$db/installed/$first/source" "$tmp/first-source"
    cp "$db/installed/$first/state" "$tmp/first-state"
    sed 's/"[^"]*"/"tampered"/' "$tmp/first-source" > "$db/installed/$first/source"
    changed=$(sha256sum "$db/installed/$first/source" | cut -d ' ' -f 1)
    sed "s/^source-record .*/source-record $changed/" "$tmp/first-state" > "$db/installed/$first/state"
    expect 5 "$bin" db recover --continue-set --root "$root"
    cp "$tmp/first-source" "$db/installed/$first/source"
    cp "$tmp/first-state" "$db/installed/$first/state"
    expect 0 "$bin" db recover --continue-set --root "$root"
    grep -qx "source-id $one" "$db/installed/$app/state"
    grep -qx "source-id $two" "$db/installed/$lib/state"
    expect 0 "$bin" db check --all --root "$root"
    cp "$tmp/interrupted-journal" "$db/transactions/set-journal"
    expect 0 "$bin" db recover --finish-set --root "$root"
    rm "$root/usr/share/app"
    expect 0 "$bin" repair first:app --root "$root"
    repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
    test "${#repair}" -eq 64
    expect 3 "$bin" repair first:app --plan "$(printf '0%.0s' $(seq 1 64))" --root "$root"
    expect 0 "$bin" repair first:app --plan "$repair" --root "$root"
    grep -qx "source-id $one" "$db/installed/$app/state"
    expect 0 "$bin" db check --all --root "$root"
fi
root="$tmp/slots"
db="$root/var/lib/holypkg"
mkdir -p "$root/usr/share"
expect 0 "$bin" db init --root "$root"
cp "$tmp/active-config" "$tmp/config"
register
package empty empty ''
rm "$tree/DATA/usr/share/empty"
"$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
mv "$tmp/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$tmp/empty2.holy" > "$tmp/out"
"$bin" cache stage "local:$tmp/empty2.holy" --root "$root" > "$tmp/out"
empty=$(hash empty2)
expect 0 "$bin" db plan-set "$empty" --source "$empty=$one" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$empty" --source "$empty=$one" --root "$root"
expect 0 "$bin" db reserve "$empty" --root "$root"
expect 4 "$bin" db plan --root "$root"
expect 0 "$bin" db cancel --root "$root"
expect 0 "$bin" db rm "$empty" --root "$root"
package alpha alpha '' shared 1
package beta beta '' shared 2
package gamma gamma '' shared 3
package delta delta '' shared 4
package collision alpha '' other 1
alpha=$(hash alpha) beta=$(hash beta) gamma=$(hash gamma) delta=$(hash delta) collision=$(hash collision)
expect 0 "$bin" db plan-set "$alpha" --source "$alpha=$one" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$alpha" --source "$alpha=$one" --root "$root"
expect 4 "$bin" db plan-set "$beta" --source "$beta=$one" --root "$root"
expect 0 "$bin" db plan-set "$beta" --source "$beta=$two" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$beta" --source "$beta=$two" --root "$root"
expect 0 "$bin" db plan-set "$gamma" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$gamma" --root "$root"
expect 4 "$bin" db plan-set "$delta" --root "$root"
expect 4 "$bin" db plan-set "$collision" --source "$collision=$two" --root "$root"
sed 's/source first/source renamed/' "$tmp/config" > "$tmp/changed"
mv "$tmp/changed" "$tmp/config"
register
expect 4 "$bin" db plan-set "$delta" --source "$delta=$one" --root "$root"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db rm "$alpha" --root "$root"
test ! -e "$root/usr/share/alpha"
grep -qx beta "$root/usr/share/beta"
grep -qx gamma "$root/usr/share/gamma"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db plan-set "$delta" --source "$delta=$one" --root "$root"
plan=$(plan_hash)
expect 0 "$bin" db apply-set "$plan" "$delta" --source "$delta=$one" --root "$root"
expect 0 "$bin" db check --all --root "$root"
printf 'installed source fixtures passed\n'
