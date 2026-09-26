#!/bin/sh
set -eu
helper=$1
bin=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name data
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for file in deps provides hooks origin transform; do : > "$tmp/payload/HOLY/$file"; done
printf 'content\n' > "$tmp/payload/DATA/usr/bin/data"
uid=$(id -u)
gid=$(id -g)
for path in usr usr/bin; do
    mode=$(stat -c %a "$tmp/payload/DATA/$path")
    printf 'dir %s %s root root %s %s 0 - none - -\n' \
        "$path" "$mode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
hash=$(sha256sum "$tmp/payload/DATA/usr/bin/data")
hash=${hash%% *}
printf 'file usr/bin/data 644 root root %s %s 8 %s none - -\n' \
    "$uid" "$gid" "$hash" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/data.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/data.tar" "$tmp/data.holy"
"$helper" "$tmp/data.holy" "$tmp/root"
cmp "$tmp/root/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
if "$helper" "$tmp/data.holy" "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
cmp "$tmp/root/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
rm "$tmp/root/usr/bin/data"
rmdir "$tmp/root/usr/bin"
ln -s "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
if "$helper" "$tmp/data.holy" "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test -L "$tmp/root/usr/bin"
cmp "$tmp/payload/DATA/usr/bin/data" "$tmp/root/usr/bin/data"
mkdir -p "$tmp/system/usr/bin"
"$bin" db init --root "$tmp/system" > "$tmp/out"
"$bin" cache stage "local:$tmp/data.holy" --root "$tmp/system" > "$tmp/out"
digest=$(sha256sum "$tmp/data.holy")
digest=${digest%% *}
"$bin" db reserve "$digest" --root "$tmp/system" > "$tmp/out"
"$bin" db plan --root "$tmp/system" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db approve "$plan" --root "$tmp/system" > "$tmp/out"
"$bin" db apply --root "$tmp/system" > "$tmp/out"
grep -qx "installed $digest generation 1 paths 3" "$tmp/out"
cmp "$tmp/system/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
db="$tmp/system/var/lib/holypkg"
for file in meta files deps origin state; do test -f "$db/installed/$digest/$file"; done
grep -qx "artifact $digest" "$db/installed/$digest/state"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 1' "$tmp/out"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
grep -qx "intact $digest generation 1" "$tmp/out"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db check "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx 'holypkg: changed-file usr/bin/data' "$tmp/err"
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
rm "$tmp/system/usr/bin/data"
ln -s "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
if "$bin" db check "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
rm "$tmp/system/usr/bin/data"
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
cp "$db/installed/$digest/state" "$tmp/saved-state"
printf 'invalid\n' > "$db/installed/$digest/state"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
cp "$tmp/saved-state" "$db/installed/$digest/state"
test ! -e "$db/transactions/pending"
test ! -e "$db/transactions/journal"
sed 's/name data/name data2/' "$tmp/payload/HOLY/meta" > "$tmp/new-meta"
mv "$tmp/new-meta" "$tmp/payload/HOLY/meta"
mv "$tmp/payload/DATA/usr/bin/data" "$tmp/payload/DATA/usr/bin/data2"
sed 's@usr/bin/data @usr/bin/data2 @' "$tmp/payload/HOLY/files" > "$tmp/new-files"
mv "$tmp/new-files" "$tmp/payload/HOLY/files"
tar -cf "$tmp/data2.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/data2.tar" "$tmp/data2.holy"
digest2=$(sha256sum "$tmp/data2.holy")
digest2=${digest2%% *}
"$bin" cache stage "local:$tmp/data2.holy" --root "$tmp/system" > "$tmp/out"
"$bin" db reserve "$digest2" --root "$tmp/system" > "$tmp/out"
"$bin" db plan --root "$tmp/system" > "$tmp/out"
plan2=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db approve "$plan2" --root "$tmp/system" > "$tmp/out"
"$bin" db apply --root "$tmp/system" > "$tmp/out"
grep -qx "installed $digest2 generation 2 paths 3" "$tmp/out"
test -f "$db/installed/$digest2/state"
test -f "$tmp/system/usr/bin/data2"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 2' "$tmp/out"
"$bin" db check "$digest2" --root "$tmp/system" > "$tmp/out"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db rm "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -e "$db/transactions/journal"
test -f "$tmp/system/usr/bin/data2"
cp "$tmp/payload/DATA/usr/bin/data2" "$tmp/system/usr/bin/data"
"$bin" db rm "$digest" --root "$tmp/system" > "$tmp/out"
grep -qx "removed $digest generation 3" "$tmp/out"
test ! -e "$tmp/system/usr/bin/data"
test ! -e "$db/installed/$digest"
test -f "$tmp/system/usr/bin/data2"
"$bin" db check "$digest2" --root "$tmp/system" > "$tmp/out"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 3' "$tmp/out"
mkdir -p "$tmp/failure/usr/bin"
"$bin" db init --root "$tmp/failure" > "$tmp/out"
"$bin" cache stage "local:$tmp/data.holy" --root "$tmp/failure" > "$tmp/out"
"$bin" db reserve "$digest" --root "$tmp/failure" > "$tmp/out"
"$bin" db plan --root "$tmp/failure" > "$tmp/out"
failure_plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db approve "$failure_plan" --root "$tmp/failure" > "$tmp/out"
printf 'keep\n' > "$tmp/failure/usr/bin/data"
if "$bin" db apply --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx keep "$tmp/failure/usr/bin/data"
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
rm "$tmp/failure/usr/bin/data"
chmod 0555 "$tmp/failure/usr/bin"
if "$bin" db apply --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
if "$bin" db status --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx 'incomplete transaction; inspect journal' "$tmp/out"
if "$bin" db recover --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test ! -e "$tmp/failure/usr/bin/data"
chmod 0755 "$tmp/failure/usr/bin"
printf 'user\n' > "$tmp/failure/usr/bin/data"
if "$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
grep -qx user "$tmp/failure/usr/bin/data"
rm "$tmp/failure/usr/bin/data"
"$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out"
grep -qx "aborted empty apply $digest; approval retained" "$tmp/out"
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
"$bin" db apply --root "$tmp/failure" > "$tmp/out"
grep -qx "installed $digest generation 1 paths 3" "$tmp/out"
chmod 0555 "$tmp/failure/usr/bin"
if "$bin" db rm "$digest" --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
if "$bin" db status --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
if "$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/usr/bin/data"
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
chmod 0755 "$tmp/failure/usr/bin"
printf 'install payload fixtures passed\n'
