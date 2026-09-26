#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/root" "$tmp/other" "$tmp/symlink" "$tmp/writable"
mkdir -p "$tmp/other/var/lib/holypkg/installed"
mkdir "$tmp/other/var/lib/holypkg/transactions" "$tmp/other/var/lib/holypkg/index"
printf 'unrecognized\n' > "$tmp/other/var/lib/holypkg/installed/unknown"
if "$bin" db init --root "$tmp/other" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
test ! -e "$tmp/other/var/lib/holypkg/generation"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
"$bin" db init --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 0' "$tmp/out"
db="$tmp/root/var/lib/holypkg"
test -d "$db/installed"
test -d "$db/transactions"
test -d "$db/index"
test "$(stat -c %a "$db/generation")" = 600
"$bin" db status --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 0' "$tmp/out"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
"$bin" db status --root "$tmp/root" --json > "$tmp/out"
grep -Fqx '{"schema":"holy-db-status-1","type":"state","generation":0,"pending":null}' "$tmp/out"
printf '7\n' > "$db/generation"
"$bin" db init --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 7' "$tmp/out"
"$bin" db status --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 7' "$tmp/out"
for area in installed transactions index; do
    printf 'unrecognized\n' > "$db/$area/unknown"
    if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    test ! -s "$tmp/out"
    grep -q "unrecognized database entries in $area" "$tmp/err"
    if "$bin" db init --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    rm "$db/$area/unknown"
done
for invalid in '07' '-1' '18446744073709551616' 'garbage'; do
    printf '%s\n' "$invalid" > "$db/generation"
    if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    test ! -s "$tmp/out"
    if "$bin" db init --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    test ! -s "$tmp/out"
done
printf '7\n' > "$db/generation"
rm "$db/generation"
ln -s "$tmp/other" "$db/generation"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
rm "$db/generation"
printf '7\n' > "$db/generation"
ln -s "$tmp/root/var" "$tmp/symlink/var"
if "$bin" db init --root "$tmp/symlink" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
chmod 777 "$tmp/writable"
if "$bin" db init --root "$tmp/writable" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/writable/var"
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name reserved
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for part in files deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$part"
done
tar -cf "$tmp/reserved.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/reserved.tar" "$tmp/reserved.holy"
digest=$(sha256sum "$tmp/reserved.holy")
digest=${digest%% *}
if "$bin" db reserve invalid --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
test ! -e "$db/transactions/pending"
if "$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -e "$db/transactions/pending"
"$bin" cache stage "local:$tmp/reserved.holy" --root "$tmp/root" > "$tmp/out"
"$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out"
grep -qx "reserved $digest generation 7" "$tmp/out"
"$bin" db preflight --root "$tmp/root" > "$tmp/out"
grep -qx "preview artifact=$digest paths=0 conflicts=0 requirements=0 elf-needed=0 script-interpreters=0 helper-commands=0" "$tmp/out"
grep -qx "reservation generation 7 artifact $digest" "$tmp/out"
object="$tmp/root/var/cache/holypkg/objects/sha256/$digest.holy"
mv "$object" "$tmp/cache-held"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
mv "$tmp/cache-held" "$object"
grep -qx 'format holy-reservation-1' "$db/transactions/pending"
grep -qx 'stage prepared' "$db/transactions/pending"
grep -qx 'generation 7' "$db/transactions/pending"
grep -qx "artifact $digest" "$db/transactions/pending"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx 'generation 7' "$tmp/out"
grep -qx "pending $digest" "$tmp/out"
if "$bin" db status --root "$tmp/root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -Fqx "{\"schema\":\"holy-db-status-1\",\"type\":\"state\",\"generation\":7,\"pending\":{\"stage\":\"prepared\",\"sha256\":\"$digest\"}}" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
temp_record="$db/transactions/.holy-tmp-00000000000000000000000000000000"
ln "$db/transactions/pending" "$temp_record"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" db recover --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx "recovered temporary reservation $digest" "$tmp/out"
test ! -e "$temp_record"
test -f "$db/transactions/pending"
cp "$db/transactions/pending" "$tmp/reservation-record"
cp "$tmp/reservation-record" "$temp_record"
if "$bin" db recover --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test -e "$temp_record"
test -e "$db/transactions/pending"
rm "$temp_record"
if "$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
if "$bin" db init --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf '8\n' > "$db/generation"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
if "$bin" db cancel --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf '7\n' > "$db/generation"
"$bin" db cancel --root "$tmp/root" > "$tmp/out"
grep -qx "cancelled $digest" "$tmp/out"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test -f "$tmp/root/var/cache/holypkg/objects/sha256/$digest.holy"
cp "$tmp/reservation-record" "$temp_record"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
"$bin" db recover --root "$tmp/root" > "$tmp/out"
grep -qx "recovered temporary reservation $digest" "$tmp/out"
test ! -e "$temp_record"
printf 'invalid\n' > "$temp_record"
if "$bin" db recover --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test -e "$temp_record"
rm "$temp_record"
"$bin" db status --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 7' "$tmp/out"
if "$bin" db cancel --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf 'require missing-1 reserved package missing any any any - missing metadata\n' > "$tmp/payload/HOLY/deps"
tar -cf "$tmp/needs.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/needs.tar" "$tmp/needs.holy"
needs=$(sha256sum "$tmp/needs.holy")
needs=${needs%% *}
"$bin" cache stage "local:$tmp/needs.holy" --root "$tmp/root" > "$tmp/out"
"$bin" db reserve "$needs" --root "$tmp/root" > "$tmp/out"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -qx "preview artifact=$needs paths=0 conflicts=0 requirements=1 elf-needed=0 script-interpreters=0 helper-commands=0" "$tmp/out"
"$bin" db cancel --root "$tmp/root" > "$tmp/out"
: > "$tmp/payload/HOLY/deps"
mkdir -p "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
printf 'hello\n' > "$tmp/payload/DATA/usr/bin/hello"
printf 'keep\n' > "$tmp/root/usr/bin/hello"
filehash=$(sha256sum "$tmp/payload/DATA/usr/bin/hello")
filehash=${filehash%% *}
uid=$(stat -c %u "$tmp/payload/DATA/usr/bin/hello")
gid=$(stat -c %g "$tmp/payload/DATA/usr/bin/hello")
for dir in usr usr/bin; do
    mode=$(stat -c %a "$tmp/payload/DATA/$dir")
    printf 'dir %s %s root root %s %s 0 - none - -\n' \
        "$dir" "$mode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
mode=$(stat -c %a "$tmp/payload/DATA/usr/bin/hello")
printf 'file usr/bin/hello %s root root %s %s 6 %s none - -\n' \
    "$mode" "$uid" "$gid" "$filehash" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/collision.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/collision.tar" "$tmp/collision.holy"
collision=$(sha256sum "$tmp/collision.holy")
collision=${collision%% *}
"$bin" cache stage "local:$tmp/collision.holy" --root "$tmp/root" > "$tmp/out"
"$bin" db reserve "$collision" --root "$tmp/root" > "$tmp/out"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx "preview artifact=$collision paths=3 conflicts=1 requirements=0 elf-needed=0 script-interpreters=0 helper-commands=0" "$tmp/out"
grep -qx 'keep' "$tmp/root/usr/bin/hello"
"$bin" db cancel --root "$tmp/root" > "$tmp/out"
printf 'postinstall /bin/sh script\n' > "$tmp/payload/HOLY/hooks"
tar -cf "$tmp/hooks.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/hooks.tar" "$tmp/hooks.holy"
hooks=$(sha256sum "$tmp/hooks.holy")
hooks=${hooks%% *}
"$bin" cache stage "local:$tmp/hooks.holy" --root "$tmp/root" > "$tmp/out"
"$bin" db reserve "$hooks" --root "$tmp/root" > "$tmp/out"
if "$bin" db preflight --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
"$bin" db cancel --root "$tmp/root" > "$tmp/out"
printf 'bad\n' > "$db/transactions/pending"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
if "$bin" db status --root "$tmp/root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
grep -Fqx '{"schema":"holy-db-status-1","type":"error","code":"invalid-state"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" db cancel --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
rm "$db/transactions/pending"
printf 'unknown\n' > "$db/transactions/other"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
rm "$db/transactions/other"
ln -s "$tmp/reserved.holy" "$db/transactions/pending"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" db cancel --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
rm "$db/transactions/pending"
test -z "$(find "$db" -name '.holy-tmp-*' -print)"
printf 'database fixtures passed\n'
