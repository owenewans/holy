#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
expect() {
    want=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then got=0; else got=$?; fi
    if test "$got" -ne "$want"; then
        printf 'expected %s, got %s: %s\n' "$want" "$got" "$*" >&2
        cat "$tmp/out" "$tmp/err" >&2
        exit 1
    fi
}
for version in old new; do
    tree="$tmp/$version"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname directories\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$version" > "$tree/HOLY/meta"
    for part in deps provides hooks origin transform; do : > "$tree/HOLY/$part"; done
    printf '%s\n' "$version" > "$tree/DATA/usr/share/payload"
    if test "$version" = new; then
        mkdir -p "$tree/DATA/opt/apps/deep"
        printf 'nested payload\n' > "$tree/DATA/opt/apps/deep/data"
        ln -s data "$tree/DATA/opt/apps/deep/link"
        chmod 750 "$tree/DATA/opt/apps"
    fi
    expect 0 "$bin" manifest generate "$tree" --output "$tmp/files"
    mv "$tmp/files" "$tree/HOLY/files"
    expect 0 "$bin" pack "$tree" --output "$tmp/$version.holy"
done
old=$(sha256sum "$tmp/old.holy" | cut -d ' ' -f 1)
new=$(sha256sum "$tmp/new.holy" | cut -d ' ' -f 1)
initialize() {
    root=$1
    mkdir "$root"
    expect 0 "$bin" db init --root "$root"
    expect 0 "$bin" cache stage "local:$tmp/old.holy" --root "$root"
    expect 0 "$bin" cache stage "local:$tmp/new.holy" --root "$root"
}
plan_set() {
    expect 0 "$bin" db plan-set "$1" --root "$root"
    plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    test "${#plan}" -eq 64
}
check_tree() {
    expect 0 "$bin" db check --all --root "$root"
    grep -qx 'nested payload' "$root/opt/apps/deep/data"
    test "$(stat -c %a "$root/opt")" = 755
    test "$(stat -c %a "$root/opt/apps")" = 750
    test "$(readlink "$root/opt/apps/deep/link")" = data
    test "$(find "$root" -name '.holy-dir-*' | wc -l)" -eq 0
}
initialize "$tmp/single"
expect 0 "$bin" db reserve "$new" --root "$root"
expect 0 "$bin" db plan --root "$root"
plan=$(sed -n 's/^plan .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test ! -e "$root/opt"
expect 0 "$bin" db approve "$plan" --root "$root"
umask 077
expect 0 "$bin" db apply --root "$root"
umask 022
check_tree
rm "$root/opt/apps/deep/data" "$root/opt/apps/deep/link"
rmdir "$root/opt/apps/deep" "$root/opt/apps" "$root/opt"
expect 4 "$bin" db check --all --root "$root"
expect 0 "$bin" db repair-plan "$new" --root "$root"
plan=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
expect 0 "$bin" db repair "$new" --plan "$plan" --root "$root"
check_tree
printf user > "$root/opt/apps/deep/untracked"
expect 0 "$bin" db rm "$new" --root "$root"
grep -qx user "$root/opt/apps/deep/untracked"
test -d "$root/opt/apps/deep"
initialize "$tmp/update"
plan_set "$old"
expect 0 "$bin" db apply-set "$plan" "$old" --root "$root"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
plan=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test ! -e "$root/opt"
expect 0 "$bin" db apply-update "$plan" "$old" "$new" --root "$root"
check_tree
initialize "$tmp/unsafe"
plan_set "$new"
mkdir "$tmp/outside"
printf sentinel > "$tmp/outside/marker"
ln -s "$tmp/outside" "$root/opt"
expect 4 "$bin" db apply-set "$plan" "$new" --root "$root"
grep -qx sentinel "$tmp/outside/marker"
test ! -e "$tmp/outside/apps"
test ! -f "$root/var/lib/holypkg/transactions/set-journal"
rm "$root/opt"
mkdir "$root/opt"
chmod 700 "$root/opt"
expect 4 "$bin" db plan-set "$new" --root "$root"
test "$(stat -c %a "$root/opt")" = 700
# payload order must not decide whether parent creation succeeds.
lz4 -dq "$tmp/new.holy" "$tmp/new.tar"
python3 - "$tmp/new.tar" "$tmp/reordered.tar" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1]) as source, tarfile.open(sys.argv[2], "w", format=tarfile.PAX_FORMAT) as output:
    members = source.getmembers()
    data = [m for m in members if m.name.startswith("DATA/")]
    order = [m for m in members if not m.name.startswith("DATA/")]
    order += [m for m in data if not m.isdir()] + list(reversed([m for m in data if m.isdir()]))
    for member in order:
        output.addfile(member, source.extractfile(member) if member.isfile() else None)
PY
lz4 -q "$tmp/reordered.tar" "$tmp/reordered.holy"
initialize "$tmp/reordered"
expect 0 "$bin" cache stage "local:$tmp/reordered.holy" --root "$root"
reordered=$(sha256sum "$tmp/reordered.holy" | cut -d ' ' -f 1)
plan_set "$reordered"
expect 0 "$bin" db apply-set "$plan" "$reordered" --root "$root"
check_tree
if "$bin" elf "$bin" | grep -q '^interpreter /'; then
    gcc -shared -fPIC -o "$tmp/fault.so" "$(dirname "$0")/update-fault.c" -ldl
    injection="LD_PRELOAD=$tmp/fault.so"
elif test "${HOLY_TEST_STATIC_UPDATE_FAULT:-0}" = 1; then
    injection="HOLY_STATIC_TEST=1"
else
    printf 'directory fault injection skipped for uninstrumented static client\n'
    printf 'directory transaction fixtures passed\n'
    exit 0
fi
for operation in set update; do
    for phase in directory-partial directory-ready directory-created payload-written; do
        if test "$operation:$phase" = update:payload-written; then continue; fi
        initialize "$tmp/$operation-$phase"
        if test "$operation" = update; then
            plan_set "$old"
            expect 0 "$bin" db apply-set "$plan" "$old" --root "$root"
            expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
            plan=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
            set -- db apply-update "$plan" "$old" "$new"
            recovery=--update
        else
            plan_set "$new"
            set -- db apply-set "$plan" "$new"
            recovery=--continue-set
        fi
        if env "$injection" HOLY_UPDATE_FAULT="$phase" HOLY_DIRECTORY_PARENT="$root" HOLY_DIRECTORY_NAME=opt \
            "$bin" "$@" --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 137; fi
        expect 5 "$bin" db status --root "$root"
        if test "$phase" = payload-written; then
            grep -qx 'nested payload' "$root/opt/apps/deep/data"
            printf changed > "$root/opt/apps/deep/data"
            expect 5 "$bin" db recover "$recovery" --root "$root"
            grep -qx changed "$root/opt/apps/deep/data"
            printf 'nested payload\n' > "$root/opt/apps/deep/data"
        fi
        if test "$phase" = directory-partial; then
            expect 5 "$bin" db recover "$recovery" --root "$root"
            test ! -e "$root/opt"
            stage="$root/.holy-dir-$(printf opt | sha256sum | cut -d ' ' -f 1)"
            test -d "$stage"
            test "$(stat -c %a "$stage")" = 700
            rmdir "$stage"
        fi
        expect 0 "$bin" db recover "$recovery" --root "$root"
        check_tree
    done
done
printf 'directory transaction fixtures passed\n'
