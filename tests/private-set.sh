#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/bin" "$tree"

expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { echo "GOT $actual WANT $expected: $*" >&2; cat "$tmp/out" >&2; cat "$tmp/err" >&2; exit 1; }
}

# two packages ship the same program name, each with its own content
program() {
    name=$1 content=$2 dependency=$3
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$content" > "$tree/DATA/usr/bin/prog"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
}

hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }

"$bin" db init --root "$root" > "$tmp/out"
program first one ''
program second two first
first=$(hash first) second=$(hash second)

# the explicit root requires the other artifact, so the set carries both and they ship
# one program name between them
root_artifact=$second
provider=$first

# one public file, two owners: the plan refuses and names the decision it needs
expect 4 "$bin" db plan-set "$root_artifact" "$provider" --root "$root"
grep -q "claim the same path: usr/bin/prog" "$tmp/err"
grep -q -- "--private $provider=usr/bin/prog or --private $second=usr/bin/prog" "$tmp/err"

# a placement for an artifact that is not in the set is still refused by the collision,
# since it does not move either copy aside
expect 4 "$bin" db plan-set "$root_artifact" "$provider" \
    --private "0000000000000000000000000000000000000000000000000000000000000000=usr/bin/prog" \
    --root "$root"

# the review says which of the two copies moves aside, and the plan names where it lands
expect 0 "$bin" db plan-set "$root_artifact" "$provider" \
    --private "$provider=usr/bin/prog" --root "$root"
grep -qx "private $provider usr/bin/prog -> usr/lib/holy/private/$provider/usr/bin/prog scope artifact-path" "$tmp/out"
chosen=$(plan_hash)

# the plan hash does not carry the decision by itself: an apply without the placement
# re-derives the same collision and refuses, since a placement is a review decision
expect 4 "$bin" db apply-set "$chosen" "$root_artifact" "$provider" --root "$root"
test ! -e "$root/usr/bin/prog"
grep -q "claim the same path: usr/bin/prog" "$tmp/err"

expect 0 "$bin" db apply-set "$chosen" "$root_artifact" "$provider" \
    --private "$provider=usr/bin/prog" --root "$root"

# the explicit root keeps the public path and the dependency's copy moves aside
test "$(cat "$root/usr/bin/prog")" = two
test "$(cat "$root/usr/lib/holy/private/$provider/usr/bin/prog")" = one
test "$(stat -c %a "$root/usr/lib/holy")" = 755

# the installed record names the private path, and the package manifest stays the
# manifest the package shipped
grep -q "usr/lib/holy/private/$provider/usr/bin/prog" \
    "$root/var/lib/holypkg/installed/$provider/files"
grep -q '"usr/bin/prog"' "$root/var/lib/holypkg/installed/$provider/package-files"
grep -q "holy-private-transform-1" "$root/var/lib/holypkg/installed/$provider/config-state"

# both packages check clean against what is installed
expect 0 "$bin" check --root "$root"

# the explicit root still requires the provider, so removing it needs the broken-edge
# decision rather than a plain removal
expect 3 "$bin" db rm "$provider" --root "$root"
test -e "$root/usr/lib/holy/private/$provider/usr/bin/prog"
expect 0 "$bin" db rm "$provider" --accept-broken --root "$root"
# the private tree belongs to the artifact that shipped the file, so removing that
# artifact takes its file and leaves the public path alone. the directories stay, the
# way a removal keeps every shared directory a manifest declared
test ! -e "$root/usr/lib/holy/private/$provider/usr/bin/prog"
test "$(cat "$root/usr/bin/prog")" = two
# the accepted removal leaves the consumer in place with a broken edge, which check
# reports rather than hides
expect 4 "$bin" check --root "$root"
grep -q "broken-provider consumer=$root_artifact" "$tmp/out" "$tmp/err"

# a displaced library is reachable only through a search path nobody has changed yet, so
# the set names every ELF that needs it instead of stranding it. the resolver requires a
# provider inside the set for each PT_INTERP and each DT_NEEDED, so this fixture
# installs a runtime first: a stub carrying libc.so.6's SONAME and the version its
# consumers require, since a provider that does not define the version does not satisfy
# the edge. the libraries carry no RUNPATH, because a search path outside the target
# root is a decision this fixture is not about.
root2="$tmp/root2"
mkdir -p "$root2/usr/lib" "$root2/usr/bin"
"$bin" db init --root "$root2" > "$tmp/out"
cc=${CC:-cc}
command -v "$cc" >/dev/null 2>&1 || { echo "$cc required for the private consumer case" >&2; exit 6; }
mkdir -p "$tmp/build"
printf 'int helper(void) { return 7; }\n' > "$tmp/helper.c"
printf 'int helper(void);\nint answer(void) { return 42 + helper(); }\n' > "$tmp/lib.c"
printf 'GLIBC_2.2.5 { global: *; };\n' > "$tmp/build/versions.map"
"$cc" -shared -fPIC -nostdlib -Wl,--version-script="$tmp/build/versions.map" \
    -Wl,-soname,libc.so.6 -o "$tmp/build/libc.so.6" -x c /dev/null
"$cc" -shared -fPIC -Wl,-soname,libhelper.so.1 -o "$tmp/build/libhelper.so.1" "$tmp/helper.c"
"$cc" -shared -fPIC -Wl,-soname,libanswer.so.1 -o "$tmp/build/libanswer.so.1" \
    "$tmp/lib.c" "$tmp/build/libhelper.so.1"

elf_package() {
    name=$1
    shift
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/lib" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch x86_64\nlibc glibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    for pair in "$@"; do
        source=${pair%%:*}
        target=${pair#*:}
        cp "$tmp/build/$source" "$tree/DATA/$target"
    done
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root2" > "$tmp/out"
}

install_set() {
    expect 0 "$bin" db plan-set "$@" --root "$root2"
    plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    expect 0 "$bin" db apply-set "$plan" "$@" --root "$root2"
}

# the runtime carries the SONAME every glibc payload names, and stays one package: two
# providers of one SONAME is a dependency conflict, a different decision from a collision
elf_package runtime libc.so.6:usr/lib/libc.so.6
runtime=$(sha256sum "$tmp/runtime.holy" | cut -d ' ' -f 1)
install_set "$runtime"

elf_package libanswer libhelper.so.1:usr/lib/libhelper.so.1 libanswer.so.1:usr/lib/libanswer.so.1
libanswer=$(sha256sum "$tmp/libanswer.holy" | cut -d ' ' -f 1)
install_set "$libanswer"

test -f "$root2/usr/lib/libanswer.so.1"

# a second provider of the helper library collides with the one already installed
elf_package other libhelper.so.1:usr/lib/libhelper.so.1
other=$(sha256sum "$tmp/other.holy" | cut -d ' ' -f 1)
# the second provider of a path an installed artifact already owns is refused by the
# preview, which reads the public path and sees the file that is there
expect 4 "$bin" db plan-set "$other" "$libanswer" --root "$root2"
grep -q "preview conflict artifact=$other path=usr/lib/libhelper.so.1" "$tmp/err"

# the placement settles the collision and names the library that needs the displaced one,
# since a private tree is reachable only through a search path nobody has changed yet
expect 3 "$bin" db plan-set "$other" "$libanswer" --private "$other=usr/lib/libhelper.so.1" \
    --root "$root2"
grep -qx "consumer $libanswer usr/lib/libanswer.so.1 needs libhelper.so.1 from $other unreachable scope soname" "$tmp/out"
test "$(grep -c '^consumer ' "$tmp/out")" -eq 1
grep -q "decision-required placement strands 1 programs" "$tmp/err"
grep -q "holypkg patch CONSUMER --runpath DIR" "$tmp/err"
test -f "$root2/usr/lib/libhelper.so.1"

echo "private placement set fixtures passed"
