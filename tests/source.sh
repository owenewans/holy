#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
mkdir "$root" "$tmp/other"
db="$root/var/lib/holypkg"
expect() {
    wanted=$1; shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then rc=0; else rc=$?; fi
    test "$rc" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
plan() {
    expect 0 "$bin" source plan --config "$tmp/config" --root "$root"
    cp "$tmp/out" "$tmp/plan"
    digest=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
}
apply() { expect 0 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"; }
"$bin" db init --root "$root" > "$tmp/out"
"$bin" db init --root "$tmp/other" > "$tmp/out"
expect 0 "$bin" source list --root "$root"
grep -qx 'revision 0 sources 0' "$tmp/out"
cat > "$tmp/config" <<'EOF'
[source primary]
type holy-http
url "https://packages.example/holy/"
trust warn
EOF
plan
test ! -e "$db/sources"
printf 'format holy-reservation-1\nstage prepared\ngeneration 0\nartifact %s\n' "$(printf '%064d' 0)" > "$db/transactions/pending"
expect 5 "$bin" source list --root "$root"
expect 5 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
expect 5 "$bin" source plan --config "$tmp/config" --root "$root"
test ! -e "$db/sources"
rm "$db/transactions/pending"
expect 3 "$bin" source apply "$tmp/plan" --sha256 "$(printf '%064d' 0)" --root "$root"
expect 3 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$tmp/other"
printf '2\n' > "$db/generation"
expect 3 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
printf '0\n' > "$db/generation"
test ! -e "$db/sources"
cp "$tmp/config" "$tmp/saved-config"
printf 'include /not/a/readable/config\n' > "$tmp/config"
apply
test "$(stat -c %a "$db/sources")" = 600
expect 0 "$bin" source list --root "$root"
id=$(sed -n 's/^source \([0-9a-f]*\) "primary" active$/\1/p' "$tmp/out")
test "${#id}" -eq 64
grep -qx 'revision 1 sources 1' "$tmp/out"
mkdir "$tmp/legacy-root"
"$bin" db init --root "$tmp/legacy-root" > "$tmp/out"
expect 0 "$bin" source plan --config "$tmp/saved-config" --root "$tmp/legacy-root"
cp "$tmp/out" "$tmp/legacy-plan"
legacy_plan=$(sha256sum "$tmp/legacy-plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/legacy-plan" --sha256 "$legacy_plan" --root "$tmp/legacy-root"
legacy_registry="$tmp/legacy-root/var/lib/holypkg/sources"
sed -e 's/^format holy-sources-2$/format holy-sources-1/' \
    -e 's/ warn - -$/ warn/' "$legacy_registry" > "$tmp/legacy-sources"
mv "$tmp/legacy-sources" "$legacy_registry"
expect 0 "$bin" source list --root "$tmp/legacy-root"
expect 0 "$bin" source plan --config "$tmp/saved-config" --root "$tmp/legacy-root"
cp "$tmp/out" "$tmp/legacy-plan"
legacy_plan=$(sha256sum "$tmp/legacy-plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/legacy-plan" --sha256 "$legacy_plan" --root "$tmp/legacy-root"
grep -qx 'format holy-sources-2' "$legacy_registry"
expect 3 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
cp "$tmp/saved-config" "$tmp/config"
plan
cp "$db/sources" "$tmp/expected"
apply
cmp "$db/sources" "$tmp/expected"
openssl genpkey -algorithm ED25519 -out "$tmp/private.pem" > "$tmp/out" 2> "$tmp/err"
openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem" > "$tmp/out" 2> "$tmp/err"
sed -e 's/source primary/source renamed/' -e 's/trust warn/trust require/' "$tmp/config" > "$tmp/renamed"
mv "$tmp/renamed" "$tmp/config"
expect 2 "$bin" source plan --config "$tmp/config" --root "$root"
printf 'public-key "public.pem"\n' >> "$tmp/config"
plan
grep -q '^alias-change ' "$tmp/err"
apply
! grep -q private.pem "$db/sources"
expect 0 "$bin" source list --root "$root"
grep -qx "source $id \"renamed\" active" "$tmp/out"
grep -qx 'revision 2 sources 1' "$tmp/out"
sed 's@packages.example/holy/@packages.example/another-repository/@' "$tmp/config" > "$tmp/changed"
mv "$tmp/changed" "$tmp/config"
plan
grep -q '^origin-change ' "$tmp/err"
apply
expect 0 "$bin" source list --root "$root"
grep -qx "source $id \"renamed\" inactive" "$tmp/out"
other=$(sed -n 's/^source \([0-9a-f]*\) "renamed" active$/\1/p' "$tmp/out")
test "$other" != "$id"
grep -qx 'revision 3 sources 2' "$tmp/out"
printf '[general]\narch x86_64\n' > "$tmp/config"
plan
apply
expect 0 "$bin" source list --root "$root"
test "$(grep -c ' inactive$' "$tmp/out")" -eq 2
grep -qx 'revision 4 sources 2' "$tmp/out"
cp "$tmp/saved-config" "$tmp/config"
plan
apply
expect 0 "$bin" source list --root "$root"
grep -qx "source $id \"primary\" active" "$tmp/out"
grep -qx 'revision 5 sources 2' "$tmp/out"
cp "$tmp/config" "$tmp/one"
sed 's/source primary/source duplicate/' "$tmp/one" >> "$tmp/config"
expect 3 "$bin" source plan --config "$tmp/config" --root "$root"
test ! -s "$tmp/out"
for url in 'https://user:secret@example.test/' 'https://example.test/?token=secret' 'https://example.test/#secret'; do
    printf '[source unsafe]\ntype holy-http\nurl "%s"\n' "$url" > "$tmp/config"
    expect 2 "$bin" source plan --config "$tmp/config" --root "$root"
    test ! -s "$tmp/out"
    ! grep -q secret "$tmp/err"
done
cat > "$tmp/config" <<'EOF'
[source arch]
type pacman
repo extra "https://mirror.example/$repo/os/$arch"
repo core "https://mirror.example/$repo/os/$arch"
EOF
plan
cp "$tmp/plan" "$tmp/ordered"
cat > "$tmp/config" <<'EOF'
[source arch]
repo core "https://mirror.example/$repo/os/$arch"
type pacman
repo extra "https://mirror.example/$repo/os/$arch"
EOF
plan
cmp "$tmp/ordered" "$tmp/plan"
cp "$db/sources" "$tmp/saved-sources"
printf corrupt > "$db/sources"
expect 1 "$bin" source list --root "$root"
expect 1 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
cp "$tmp/saved-sources" "$db/sources"
mv "$db/sources" "$tmp/regular"
ln -s "$tmp/regular" "$db/sources"
expect 1 "$bin" source list --root "$root"
expect 1 "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
rm "$db/sources"
mv "$tmp/regular" "$db/sources"
python3 - "$tmp/plan" "$tmp/forged" "$id" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text().splitlines(True)
pathlib.Path(sys.argv[2]).write_text(''.join(x for x in lines if not x.startswith('source '+sys.argv[3]+' ')))
PY
forged=$(sha256sum "$tmp/forged" | cut -d ' ' -f 1)
expect 3 "$bin" source apply "$tmp/forged" --sha256 "$forged" --root "$root"
cmp "$db/sources" "$tmp/saved-sources"
sed "s/$id/$(printf '%064d' 0)/g" "$tmp/plan" > "$tmp/invalid-identity"
forged=$(sha256sum "$tmp/invalid-identity" | cut -d ' ' -f 1)
expect 2 "$bin" source apply "$tmp/invalid-identity" --sha256 "$forged" --root "$root"
cmp "$db/sources" "$tmp/saved-sources"
if test "${HOLY_SOURCE_STATIC:-0}" != 1; then
    cat > "$tmp/fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
int renameat(int from, const char *old, int to, const char *next)
{
    int (*actual)(int, const char *, int, const char *);
    void *symbol = dlsym(RTLD_NEXT, "renameat");
    if (!strcmp(next, "sources")) { errno = ENOSPC; return -1; }
    memcpy(&actual, &symbol, sizeof actual);
    if (!actual) abort();
    return actual(from, old, to, next);
}
C
    gcc -shared -fPIC -o "$tmp/fault.so" "$tmp/fault.c" -ldl
    expect 1 env LD_PRELOAD="$tmp/fault.so" "$bin" source apply "$tmp/plan" --sha256 "$digest" --root "$root"
    cmp "$db/sources" "$tmp/saved-sources"
fi
apply
test "$(cat "$db/generation")" -eq 0
expect 0 "$bin" db status --root "$root"
if test "${HOLY_SOURCE_CHROOT:-0}" = 1; then
    command -v doas >/dev/null && doas -n true || exit 6
    test ! -e "$root/lib" && test ! -e "$root/lib64" && test ! -e "$root/usr/lib"
    mkdir "$root/tmp"
    cp "$bin" "$root/source-client"
    cp "$tmp/config" "$root/config"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client source plan --config /config --root /
    cp "$tmp/out" "$root/plan"
    digest=$(sha256sum "$root/plan" | cut -d ' ' -f 1)
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client source apply /plan --sha256 "$digest" --root /
    expect 0 "$bin" source list --root "$root"
    cp "$tmp/out" "$tmp/expected-list"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /source-client source list --root /
    cmp "$tmp/out" "$tmp/expected-list"
fi
printf 'source registry fixtures passed\n'
