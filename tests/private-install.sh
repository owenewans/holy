#!/bin/sh
set -eu
helper=$1
bin=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

artifact=06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e
private=usr/lib/holy/private/$artifact

# a package that ships one program the public tree already holds, plus one it does not
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name displaced
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for file in files deps provides hooks origin transform; do : > "$tmp/payload/HOLY/$file"; done
printf 'second\n' > "$tmp/payload/DATA/usr/bin/prog"
printf 'only\n' > "$tmp/payload/DATA/usr/bin/alone"
"$bin" manifest generate "$tmp/payload" --output "$tmp/generated-files" > /dev/null
cp "$tmp/generated-files" "$tmp/payload/HOLY/files"
tar -cf "$tmp/pkg.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/pkg.tar" "$tmp/pkg.holy"

# the public path already belongs to another provider
printf 'first\n' > "$tmp/root/usr/bin/prog"
chmod 755 "$tmp/root/usr/bin/prog"

if ! "$helper" --placed "$tmp/pkg.holy" "$artifact" "$tmp/root" "usr/bin/prog" > "$tmp/out" 2> "$tmp/err"; then
    cat "$tmp/err" >&2
    find "$tmp/root" >&2
    exit 1
fi

test "$(cat "$tmp/root/usr/bin/prog")" = first
test "$(cat "$tmp/root/$private/usr/bin/prog")" = second
test "$(cat "$tmp/root/usr/bin/alone")" = only
test ! -e "$tmp/root/$private/usr/bin/alone"

# the private tree keeps the structure the package shipped, so a placed program finds
# its neighbors where it expects them
test -d "$tmp/root/usr/lib/holy/private"
test "$(stat -c %a "$tmp/root/usr/lib/holy")" = 755

# a placement naming a path the package does not ship is refused, since it would be a
# decision about a file that is not there
fresh=$(mktemp -d)
if "$helper" --placed "$tmp/pkg.holy" "$artifact" "$fresh" "usr/bin/missing" > "$tmp/out" 2> "$tmp/err"; then
    exit 1
fi
test ! -e "$fresh/usr"
rm -rf "$fresh"

# an artifact id that is not one is refused before anything is written
fresh=$(mktemp -d)
if "$helper" --placed "$tmp/pkg.holy" "$(printf 'z%.0s' 1 2 3 4 5 6 7 8 9)" "$fresh" "usr/bin/prog" > "$tmp/out" 2> "$tmp/err"; then
    exit 1
fi
test ! -e "$fresh/usr"
rm -rf "$fresh"

echo "private install fixture ok"