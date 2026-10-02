#!/bin/sh
# the published page and its plain-text twin are generated from the directory that was
# published, so the fixture checks that they describe the index rather than a list typed
# by hand: every package record becomes a row, a package the index does not carry does
# not, the generation comes from current, and a missing index or an unsigned generation is
# stated rather than hidden.
set -eu

bin=${1:-./holypkg}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
page=$repo/tools/packages-page.sh

test -f "$page" || { printf 'packages page: %s is not a file\n' "$page" >&2; exit 6; }

# one real static package is enough: the page reads the index, not the payload. its arch
# is the host's, since the packer refuses a payload that contradicts its own metadata
case $(uname -m) in
    x86_64) arch=x86_64 ;;
    i?86) arch=x86 ;;
    *) arch=noarch ;;
esac
mkdir -p "$tmp/tree/DATA/usr/bin" "$tmp/tree/HOLY" "$tmp/mirror" "$tmp/site"
printf '.global _start\n_start:\n mov $60, %%rax\n xor %%rdi, %%rdi\n syscall\n' > "$tmp/helper.s"
"${CC:-cc}" -nostdlib -static -o "$tmp/helper" "$tmp/helper.s" 2>/dev/null ||
    { printf 'packages page: a static C compiler is required\n' >&2; exit 6; }
printf 'format holy-package-1\nname page-one\nversion 1.0\nrelease 1\nos linux\narch %s\nlibc nolibc\n' "$arch" \
    > "$tmp/tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
cp "$tmp/helper" "$tmp/tree/DATA/usr/bin/page-helper"
"$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
mv "$tmp/files" "$tmp/tree/HOLY/files"
"$bin" pack "$tmp/tree" --output "$tmp/mirror/page-one.holy" > "$tmp/out"
"$bin" repo index "$tmp/mirror" > "$tmp/out"
"$bin" repo seal "$tmp/mirror" > "$tmp/out"
generation=$(sed -n 's/^sha256 //p' "$tmp/mirror/current")
test "${#generation}" = 64

# the page needs an index and a current pointer, and says so when one is absent
mkdir -p "$tmp/bare"
if sh "$page" "$tmp/bare" "$tmp/site" > "$tmp/out" 2> "$tmp/err"; then
    printf 'packages page: an empty directory produced a page\n' >&2
    exit 1
fi
grep -q 'is not a file' "$tmp/err"

# the unsigned generation is stated, not implied
mkdir -p "$tmp/unsigned"
cp "$tmp/mirror/index" "$tmp/mirror/current" "$tmp/unsigned/"
sh "$page" "$tmp/unsigned" "$tmp/site" > "$tmp/out"
grep -q 'signature unsigned' "$tmp/site/index.html"
grep -q 'signature   unsigned' "$tmp/site/packages.txt"

sh "$page" "$tmp/mirror" "$tmp/site" > "$tmp/out"
grep -q "generation ${generation%"${generation#????????????}"}" "$tmp/out"

# every package record of the index is a row, and each row is a link that resolves to a
# file the directory actually holds
rows=$(sed -n 's/.*<li><a href="\/\([^"]*\)">[^<]*<\/a>.*/\1/p' "$tmp/site/index.html" | wc -l)
packages=$(sed -n 's/^package "\([^"]*\)".*/\1/p' "$tmp/mirror/index" | wc -l)
test "$rows" -eq "$packages" || {
    printf 'packages page: %s rows for %s index records\n' "$rows" "$packages" >&2
    exit 1
}
for file in $(sed -n 's/.*<li><a href="\/\([^"]*\)">.*/\1/p' "$tmp/site/index.html"); do
    test -f "$tmp/mirror/$file" || {
        printf 'packages page: the page links %s and the directory has no such file\n' "$file" >&2
        exit 1
    }
done

# a package the index does not carry is not on the page
grep -q 'page-one' "$tmp/site/index.html"
if grep -q 'page-absent' "$tmp/site/index.html"; then
    printf 'packages page: the page names a package the index lacks\n' >&2
    exit 1
fi

# the generation on the page is the one current names, and the index row is the one the
# directory holds
grep -q "$generation" "$tmp/site/index.html"
grep -q "$generation" "$tmp/site/packages.txt"
grep -q 'holy packages' "$tmp/site/index.html"
grep -q 'holy packages' "$tmp/site/packages.txt"

# the page must not carry template syntax, since the server renders it as one
if grep -q '{{' "$tmp/site/index.html"; then
    printf 'packages page: the html carries go template braces\n' >&2
    exit 1
fi

printf 'packages page fixtures passed\n'
