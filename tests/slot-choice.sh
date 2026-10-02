#!/bin/sh
# a native repository may carry one package name for several architectures, since a slot
# is the name, os, arch and libc together. the manager does not pick a slot for the
# caller, so it reports the ambiguity and --arch or --libc is the choice. the fixture is
# two real static packages of the same name on two architectures, because a name that
# only the index claims would not prove that a downloaded artifact agrees.
set -eu

bin=${1:-./holypkg}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

expect() {
    want=$1; shift
    rc=0
    "$@" >"$tmp/out" 2>"$tmp/err" || rc=$?
    if test "$rc" != "$want"; then
        printf 'slot fixture: %s returned %s, expected %s\n' "$1" "$rc" "$want" >&2
        cat "$tmp/out" "$tmp/err" >&2
        exit 1
    fi
}

case $(uname -m) in
    x86_64) arch=x86_64 ;;
    i?86) arch=x86 ;;
    *) printf 'slot fixture: needs x86 or x86_64, not %s\n' "$(uname -m)" >&2; exit 6 ;;
esac

# one static helper per architecture, so each artifact is a real ELF the scanner accepts.
# the 32-bit one needs a multilib compiler, and a host without it reports a requirement
# rather than a fixture that cannot exist here
build_helper() {
    target=$1; output=$2
    case $target in
        x86_64)
            printf '.global _start\n_start:\n mov $60, %%rax\n xor %%rdi, %%rdi\n syscall\n' \
                > "$tmp/$target.s"
            "${CC:-cc}" -nostdlib -static -o "$tmp/$output" "$tmp/$target.s"
            ;;
        x86)
            printf '.global _start\n_start:\n mov $1, %%eax\n xor %%ebx, %%ebx\n int $0x80\n' \
                > "$tmp/$target.s"
            "${CC:-cc}" -m32 -nostdlib -static -o "$tmp/$output" "$tmp/$target.s" 2>/dev/null ||
                { printf 'slot fixture: a 32-bit compiler is required\n' >&2; exit 6; }
            ;;
    esac
}

make_package() {
    target=$1; name=$2; libc=$3; output=$4
    rm -rf "$tmp/tree"
    mkdir -p "$tmp/tree/DATA/usr/bin" "$tmp/tree/HOLY"
    printf 'format holy-package-1\nname %s\nversion 1.0\nrelease 1\nos linux\narch %s\nlibc %s\n' \
        "$name" "$target" "$libc" > "$tmp/tree/HOLY/meta"
    for field in files deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
    cp "$tmp/helper-$target" "$tmp/tree/DATA/usr/bin/slot-helper-$target"
    # the generator writes outside the tree it reads, so the record moves in afterwards
    "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tmp/tree/HOLY/files"
    "$bin" pack "$tmp/tree" --output "$tmp/repo/$output" > "$tmp/out"
}

build_helper x86_64 helper-x86_64
build_helper x86 helper-x86
mkdir -p "$tmp/repo"
make_package x86_64 slot-two nolibc slot-two-x86_64.holy
make_package x86 slot-two nolibc slot-two-x86.holy
# a second name that only one architecture carries, so a filter has something to exclude
make_package x86_64 slot-one nolibc slot-one-x86_64.holy

"$bin" repo index "$tmp/repo" > "$tmp/out"
grep -qx 'indexed 3 packages' "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"

# the name alone is a choice the caller has to make
expect 3 "$bin" repo requirements "$tmp/repo" slot-two
grep -q 'requires an architecture/ABI choice' "$tmp/err"

# each filter selects exactly one artifact
expect 0 "$bin" repo requirements "$tmp/repo" slot-two --arch x86_64
grep -q '"x86_64"' "$tmp/out"
expect 0 "$bin" repo requirements "$tmp/repo" slot-two --arch x86
grep -q '^package "slot-two" "1.0" "1" "linux" "x86" "nolibc"' "$tmp/out"

# a libc narrows only what it can: two artifacts of one name and one libc are still two
# slots, so the choice stands until an arch joins it
expect 3 "$bin" repo requirements "$tmp/repo" slot-two --libc nolibc
grep -q 'requires an architecture/ABI choice' "$tmp/err"
expect 0 "$bin" repo requirements "$tmp/repo" slot-two --libc nolibc --arch x86
grep -q '^package "slot-two" "1.0" "1" "linux" "x86" "nolibc"' "$tmp/out"
# a libc the catalog has no artifact for is a missing slot, not another package
expect 6 "$bin" repo requirements "$tmp/repo" slot-two --libc glibc
grep -q 'has no artifact of that arch and libc' "$tmp/err"

# a slot the catalog does not have is a different answer from a name it does not carry
expect 6 "$bin" repo requirements "$tmp/repo" slot-two --arch aarch64
grep -q 'has no artifact of that arch and libc' "$tmp/err"
expect 6 "$bin" repo requirements "$tmp/repo" slot-one --arch x86
grep -q 'has no artifact of that arch and libc' "$tmp/err"
expect 6 "$bin" repo requirements "$tmp/repo" slot-absent --arch x86_64
grep -q 'not found' "$tmp/err"
expect 6 "$bin" repo requirements "$tmp/repo" slot-absent
grep -q 'not found' "$tmp/err"

# the index itself is unchanged by a query
cp "$tmp/repo/index" "$tmp/index-before"
"$bin" repo requirements "$tmp/repo" slot-two --arch x86_64 > "$tmp/out"
cmp "$tmp/index-before" "$tmp/repo/index"

# the same choice at the source level, where a real configuration names the mirror
cat > "$tmp/sources" <<'CONF'
[source fixture]
type holy-http
url "https://fixture.example/holy/"
CONF
# the database lives under the root, so the root itself has to exist first
mkdir -p "$tmp/root"
"$bin" db init --root "$tmp/root" > "$tmp/out"
"$bin" source plan --config "$tmp/sources" --root "$tmp/root" > "$tmp/plan"
"$bin" source apply "$tmp/plan" --sha256 "$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)" \
    --root "$tmp/root" > "$tmp/out"
# a bound catalog has to state which source it came from and which generation, so the
# binding is checked rather than assumed
"$bin" source list --root "$tmp/root" > "$tmp/out"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/out")
test -n "$source_id"
index_sha=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$index_sha" "$source_id" > "$tmp/repo/mirror-origin"
"$bin" source catalog bind fixture "$tmp/repo" --root "$tmp/root" > "$tmp/out"

expect 3 "$bin" info fixture:slot-two --root "$tmp/root"
grep -q 'requires an architecture/ABI choice' "$tmp/err"
expect 0 "$bin" info fixture:slot-two --arch x86_64 --root "$tmp/root"
grep -q '"x86_64"' "$tmp/out"
expect 6 "$bin" info fixture:slot-two --arch aarch64 --root "$tmp/root"
grep -q 'has no artifact of that arch and libc' "$tmp/err"
# a search is a listing, not a selection: both slots of one name are reported and
# neither is preferred, which is what leaves the choice to info and add
expect 0 "$bin" search slot-two --root "$tmp/root"
grep -q 'listed 2 packages' "$tmp/out"
grep -q '"x86"' "$tmp/out" && grep -q '"x86_64"' "$tmp/out"

printf 'slot choice fixtures passed\n'
