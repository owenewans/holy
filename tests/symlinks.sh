#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
tree="$tmp/tree"
root="$tmp/root"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/share/man/man8" "$root/usr/share/man/man8"
cat > "$tree/HOLY/meta" <<'EOF'
format holy-package-1
name link-fixture
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
printf 'manual\n' > "$tree/DATA/usr/share/man/man8/dinit.8"
ln -s dinit.8 "$tree/DATA/usr/share/man/man8/dinitctl.8"
ln -s 'missing "manual"' "$tree/DATA/usr/share/man/man8/dangling.8"
ln -s usr "$tree/DATA/alias"
"$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
cp "$tmp/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$tmp/links.holy" > "$tmp/out"
digest=$(sha256sum "$tmp/links.holy")
digest=${digest%% *}
"$bin" db init --root "$root" > "$tmp/out"
"$bin" cache stage "local:$tmp/links.holy" --root "$root" > "$tmp/out"
prepare() {
    "$bin" db reserve "$digest" --root "$root" > "$tmp/out"
    "$bin" db plan --root "$root" > "$tmp/out"
    plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    test "${#plan}" -eq 64
    "$bin" db approve "$plan" --root "$root" > "$tmp/out"
}
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq "$wanted"; fi
}
prepare
"$bin" db apply --root "$root" > "$tmp/out"
"$bin" db check "$digest" --root "$root" > "$tmp/out"
test "$(readlink "$root/alias")" = usr
test "$(readlink "$root/usr/share/man/man8/dangling.8")" = 'missing "manual"'
cmp "$root/usr/share/man/man8/dinitctl.8" "$tree/DATA/usr/share/man/man8/dinit.8"
"$bin" db owner usr/share/man/man8/dinitctl.8 --root "$root" > "$tmp/out"
grep -q "^$digest " "$tmp/out"
db="$root/var/lib/holypkg"
link="$root/usr/share/man/man8/dinitctl.8"
rm "$link"
ln -s dangling.8 "$link"
expect 4 "$bin" db check "$digest" --root "$root" --json
grep -q 'changed-file' "$tmp/out"
expect 4 "$bin" db rm "$digest" --root "$root"
test ! -e "$db/transactions/journal"
rm "$link"
expect 4 "$bin" db check "$digest" --root "$root" --json
grep -q 'missing-file' "$tmp/out"
cp "$tree/DATA/usr/share/man/man8/dinit.8" "$link"
expect 4 "$bin" db rm "$digest" --root "$root"
rm "$link"
ln -s dinit.8 "$link"
other=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
cp -a "$db/installed/$digest" "$db/installed/$other"
sed "s/$digest/$other/" "$db/installed/$digest/state" > "$db/installed/$other/state"
expect 4 "$bin" db owner usr/share/man/man8/dinitctl.8 --root "$root"
expect 4 "$bin" db rm "$digest" --root "$root"
test -L "$link"
rm -r "$db/installed/$other"
"$bin" db rm "$digest" --root "$root" > "$tmp/out"
test ! -L "$root/alias"
test ! -L "$root/usr/share/man/man8/dangling.8"
test ! -e "$link"
test -d "$root/usr/share/man/man8"
prepare
ln -s absent "$link"
expect 4 "$bin" db apply --root "$root"
test ! -e "$db/transactions/journal"
test "$(readlink "$link")" = absent
rm "$link"
"$bin" db apply --root "$root" > "$tmp/out"
generation=$(cat "$db/generation")
printf 'format holy-journal-1\nstage removing\ngeneration %s\nartifact %s\nplan %064d\n' \
    "$generation" "$digest" 0 > "$db/transactions/journal"
rm "$root/alias"
rm "$link"
ln -s changed "$link"
expect 5 "$bin" db recover --continue --root "$root"
test -f "$root/usr/share/man/man8/dinit.8"
test -L "$root/usr/share/man/man8/dangling.8"
rm "$link"
"$bin" db recover --continue --root "$root" > "$tmp/out"
test ! -e "$db/transactions/journal"
test ! -e "$db/installed/$digest"
test ! -L "$root/usr/share/man/man8/dangling.8"
test ! -e "$root/usr/share/man/man8/dinit.8"
prepare
generation=$(cat "$db/generation")
printf 'format holy-journal-1\nstage applying\ngeneration %s\nartifact %s\nplan %s\n' \
    "$generation" "$digest" "$plan" > "$db/transactions/journal"
ln -s usr "$root/alias"
expect 5 "$bin" db recover --abort-empty --root "$root"
test -L "$root/alias"
rm "$root/alias"
"$bin" db recover --abort-empty --root "$root" > "$tmp/out"
"$bin" db cancel --root "$root" > "$tmp/out"
mv "$root/usr/share/man/man8" "$tmp/outside"
ln -s "$tmp/outside" "$root/usr/share/man/man8"
"$bin" db reserve "$digest" --root "$root" > "$tmp/out"
expect 4 "$bin" db plan --root "$root"
test ! -L "$tmp/outside/dinitctl.8"
test ! -e "$tmp/outside/dinit.8"
printf 'symlink transaction fixtures passed\n'
