#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/bin"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name fixture
version 1.0
release 1
os linux
arch x86_64
libc nolibc
EOF
printf 'hello\n' > "$tmp/payload/DATA/usr/bin/hello"
for member in deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$member"
done
digest=$(sha256sum "$tmp/payload/DATA/usr/bin/hello" | cut -d ' ' -f 1)
mode=$(stat -c %a "$tmp/payload/DATA/usr/bin/hello")
uid=$(stat -c %u "$tmp/payload/DATA/usr/bin/hello")
gid=$(stat -c %g "$tmp/payload/DATA/usr/bin/hello")
printf 'file usr/bin/hello %s root root %s %s 6 %s none - -\n' \
    "$mode" "$uid" "$gid" "$digest" > "$tmp/payload/HOLY/files"
for dir in usr usr/bin; do
    dmode=$(stat -c %a "$tmp/payload/DATA/$dir")
    printf 'dir %s %s root root %s %s 0 - none - -\n' \
        "$dir" "$dmode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/payload.tar" "$tmp/package.holy"
"$bin" info "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'name fixture' "$tmp/out"
grep -qx 'libc nolibc' "$tmp/out"
expected=$(sha256sum "$tmp/package.holy" | cut -d ' ' -f 1)
grep -qx "sha256 $expected" "$tmp/out"
"$bin" requirements "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'requirements 0' "$tmp/out"
cp -a "$tmp/payload" "$tmp/with-deps"
printf 'require libc-1 package soname libc.so.6 x86_64 glibc any - "libc.so.6" metadata\n' > "$tmp/with-deps/HOLY/deps"
tar -cf "$tmp/with-deps.tar" -C "$tmp/with-deps" HOLY DATA
lz4 -q "$tmp/with-deps.tar" "$tmp/with-deps.holy"
"$bin" requirements "local:$tmp/with-deps.holy" > "$tmp/out"
grep -qx 'requirements 1' "$tmp/out"
grep -Fqx 'require "libc-1" "package" "soname" "libc.so.6" "x86_64" "glibc" "any" "-" "libc.so.6" "metadata"' "$tmp/out"
"$bin" requirements "local:$tmp/with-deps.holy" --json > "$tmp/out"
grep -Fqx '{"schema":"holy-requirements-1","type":"requirement","id":"libc-1","consumer":"package","kind":"soname","name":"libc.so.6","arch":"x86_64","libc":"glibc","relation":"any","version":"-","original":"libc.so.6","evidence":"metadata"}' "$tmp/out"
grep -Fqx '{"schema":"holy-requirements-1","type":"summary","count":1}' "$tmp/out"
printf 'require libc-1 package soname libc.so.6 x86_64 glibc any - original duplicate\n' >> "$tmp/with-deps/HOLY/deps"
tar -cf "$tmp/with-deps.tar" -C "$tmp/with-deps" HOLY DATA
lz4 -q -f "$tmp/with-deps.tar" "$tmp/with-deps.holy"
if "$bin" requirements "local:$tmp/with-deps.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
grep -q 'duplicate requirement id' "$tmp/err"
if "$bin" requirements "local:$tmp/with-deps.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -Fqx '{"schema":"holy-requirements-1","type":"error","code":"invalid-requirements"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
printf 'alternative unsupported\n' > "$tmp/with-deps/HOLY/deps"
tar -cf "$tmp/with-deps.tar" -C "$tmp/with-deps" HOLY DATA
lz4 -q -f "$tmp/with-deps.tar" "$tmp/with-deps.holy"
if "$bin" requirements "local:$tmp/with-deps.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
grep -q 'unsupported requirement' "$tmp/err"
printf '%s\n' 'require escaped package file /tmp/probe any any any - "line\nfeed" metadata' > "$tmp/with-deps/HOLY/deps"
tar -cf "$tmp/with-deps.tar" -C "$tmp/with-deps" HOLY DATA
lz4 -q -f "$tmp/with-deps.tar" "$tmp/with-deps.holy"
"$bin" requirements "local:$tmp/with-deps.holy" --json > "$tmp/out"
grep -Fq '"original":"line\u000afeed"' "$tmp/out"
grep -Fqx '{"schema":"holy-requirements-1","type":"summary","count":1}' "$tmp/out"
mkdir "$tmp/preview-root"
"$bin" preview "local:$tmp/package.holy" --root "$tmp/preview-root" > "$tmp/out"
grep -qx "preview artifact=$expected paths=3 conflicts=0 requirements=0" "$tmp/out"
grep -qx 'new usr/bin/hello' "$tmp/out"
test ! -e "$tmp/preview-root/usr"
mkdir "$tmp/preview-root/usr"
ln -s "$tmp/payload/DATA/usr/bin" "$tmp/preview-root/usr/bin"
rc=0
"$bin" preview "local:$tmp/package.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 4
grep -qx "preview artifact=$expected paths=3 conflicts=2 requirements=0" "$tmp/out"
grep -qx 'conflict usr/bin/hello' "$tmp/out"
test -L "$tmp/preview-root/usr/bin"
rm "$tmp/preview-root/usr/bin"
mkdir "$tmp/preview-root/usr/bin"
printf 'keep\n' > "$tmp/preview-root/usr/bin/hello"
rc=0
"$bin" preview "local:$tmp/package.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 4
grep -qx "preview artifact=$expected paths=3 conflicts=1 requirements=0" "$tmp/out"
grep -qx 'conflict usr/bin/hello' "$tmp/out"
grep -qx 'keep' "$tmp/preview-root/usr/bin/hello"
cp -a "$tmp/payload" "$tmp/with-hook"
printf 'run /bin/sh script\n' > "$tmp/with-hook/HOLY/hooks"
tar -cf "$tmp/with-hook.tar" -C "$tmp/with-hook" HOLY DATA
lz4 -q "$tmp/with-hook.tar" "$tmp/with-hook.holy"
rc=0
"$bin" preview "local:$tmp/with-hook.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 6
test ! -s "$tmp/out"
grep -q 'requires empty hooks' "$tmp/err"
: > "$tmp/with-hook/HOLY/hooks"
printf 'require unknown\n' > "$tmp/with-hook/HOLY/deps"
tar -cf "$tmp/with-hook.tar" -C "$tmp/with-hook" HOLY DATA
lz4 -q -f "$tmp/with-hook.tar" "$tmp/with-hook.holy"
rc=0
"$bin" preview "local:$tmp/with-hook.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 2
test ! -s "$tmp/out"
cp "$tmp/with-deps/HOLY/deps" "$tmp/with-hook/HOLY/deps"
tar -cf "$tmp/with-hook.tar" -C "$tmp/with-hook" HOLY DATA
lz4 -q -f "$tmp/with-hook.tar" "$tmp/with-hook.holy"
mkdir "$tmp/decision-root"
rc=0
"$bin" preview "local:$tmp/with-hook.holy" --root "$tmp/decision-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 3
grep -q '^preview artifact=.* paths=3 conflicts=0 requirements=1$' "$tmp/out"
test ! -e "$tmp/decision-root/usr"
rc=0
"$bin" preview "local:$tmp/with-hook.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 4
grep -q '^preview artifact=.* paths=3 conflicts=1 requirements=1$' "$tmp/out"
cp -a "$tmp/payload" "$tmp/privileged"
chmod 4755 "$tmp/privileged/DATA/usr/bin/hello"
sed 's/^file usr\/bin\/hello [^ ]*/file usr\/bin\/hello 4755/' \
    "$tmp/payload/HOLY/files" > "$tmp/privileged/HOLY/files"
tar -cf "$tmp/privileged.tar" -C "$tmp/privileged" HOLY DATA
lz4 -q "$tmp/privileged.tar" "$tmp/privileged.holy"
"$bin" verify "local:$tmp/privileged.holy" > "$tmp/out"
rc=0
"$bin" preview "local:$tmp/privileged.holy" --root "$tmp/preview-root" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 6
test ! -s "$tmp/out"
grep -q 'privileged payload mode requires review' "$tmp/err"
cp -a "$tmp/payload" "$tmp/elf-payload"
sed 's/^libc nolibc$/libc glibc/' "$tmp/payload/HOLY/meta" > "$tmp/elf-payload/HOLY/meta"
printf '#include <stdio.h>\nint main(void) { return puts("probe") < 0; }\n' > "$tmp/probe.c"
gcc -o "$tmp/elf-payload/DATA/usr/bin/probe" "$tmp/probe.c"
gcc -shared -fPIC -Wl,-soname,plugin.so.1 -o "$tmp/elf-payload/DATA/usr/bin/plugin.so" "$tmp/probe.c"
for file in probe plugin.so; do
    path="$tmp/elf-payload/DATA/usr/bin/$file"
    printf 'file usr/bin/%s %s root root %s %s %s %s none - -\n' \
        "$file" "$(stat -c %a "$path")" "$uid" "$gid" \
        "$(stat -c %s "$path")" "$(sha256sum "$path" | cut -d ' ' -f 1)" \
        >> "$tmp/elf-payload/HOLY/files"
done
tar -cf "$tmp/elf.tar" -C "$tmp/elf-payload" HOLY DATA
lz4 -q "$tmp/elf.tar" "$tmp/elf.holy"
TMPDIR="$tmp" "$bin" scan "local:$tmp/elf.holy" > "$tmp/out"
grep -q '^elf usr/bin/probe class=ELF64 machine=x86_64 e_machine=62 runtime=glibc ' "$tmp/out"
grep -q '^elf usr/bin/plugin.so class=ELF64 machine=x86_64 e_machine=62 runtime=unknown ' "$tmp/out"
grep -qx 'soname usr/bin/plugin.so plugin.so.1' "$tmp/out"
grep -qx 'needed usr/bin/probe libc.so.6' "$tmp/out"
grep -q '^version usr/bin/probe libc.so.6 GLIBC_.* required$' "$tmp/out"
grep -qx 'scanned 2 ELF files' "$tmp/out"
test -z "$(find "$tmp" -maxdepth 1 -name 'holy-scan-*' -print)"
cp -a "$tmp/elf-payload" "$tmp/plugin-only"
rm "$tmp/plugin-only/DATA/usr/bin/probe"
grep -v '^file usr/bin/probe ' "$tmp/elf-payload/HOLY/files" > "$tmp/plugin-only/HOLY/files"
for tag in nolibc musl; do
    sed "s/^libc glibc$/libc $tag/" "$tmp/elf-payload/HOLY/meta" > "$tmp/plugin-only/HOLY/meta"
    tar -cf "$tmp/plugin-only.tar" -C "$tmp/plugin-only" HOLY DATA
    lz4 -q -f "$tmp/plugin-only.tar" "$tmp/plugin-only.holy"
    "$bin" verify "local:$tmp/plugin-only.holy" > "$tmp/out"
    if "$bin" scan "local:$tmp/plugin-only.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    grep -q 'ELF requires libc.so.6 but package libc differs' "$tmp/err"
    if "$bin" check "local:$tmp/plugin-only.holy" --root "$tmp/preview-root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    grep -qx '{"schema":"holy-check-1","code":"invalid-package","severity":"error","status":"unknown"}' "$tmp/out"
done
cp "$tmp/elf-payload/HOLY/meta" "$tmp/elf-meta"
for mismatch in arch libc noarch; do
    case "$mismatch" in
        arch) sed 's/^arch x86_64$/arch x86/' "$tmp/elf-meta" > "$tmp/elf-payload/HOLY/meta" ;;
        libc) sed 's/^libc glibc$/libc musl/' "$tmp/elf-meta" > "$tmp/elf-payload/HOLY/meta" ;;
        noarch) sed -e 's/^arch x86_64$/arch noarch/' -e 's/^libc glibc$/libc nolibc/' \
            "$tmp/elf-meta" > "$tmp/elf-payload/HOLY/meta" ;;
    esac
    tar -cf "$tmp/elf-mismatch.tar" -C "$tmp/elf-payload" HOLY DATA
    lz4 -q -f "$tmp/elf-mismatch.tar" "$tmp/elf-mismatch.holy"
    "$bin" verify "local:$tmp/elf-mismatch.holy" > "$tmp/out"
    if "$bin" scan "local:$tmp/elf-mismatch.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    if "$bin" check "local:$tmp/elf-mismatch.holy" --root "$tmp/preview-root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    grep -qx '{"schema":"holy-check-1","code":"invalid-package","severity":"error","status":"unknown"}' "$tmp/out"
    if test "$mismatch" = libc; then
        grep -q 'libc differs\|arch/libc mismatch' "$tmp/err"
    else
        grep -q 'ELF arch/libc mismatch' "$tmp/err"
    fi
done
cp "$tmp/elf-meta" "$tmp/elf-payload/HOLY/meta"
printf '\177ELFbroken\n' > "$tmp/elf-payload/DATA/usr/bin/probe"
grep -v '^file usr/bin/probe ' "$tmp/elf-payload/HOLY/files" > "$tmp/elf-files"
path="$tmp/elf-payload/DATA/usr/bin/probe"
printf 'file usr/bin/probe %s root root %s %s %s %s none - -\n' \
    "$(stat -c %a "$path")" "$uid" "$gid" "$(stat -c %s "$path")" \
    "$(sha256sum "$path" | cut -d ' ' -f 1)" >> "$tmp/elf-files"
mv "$tmp/elf-files" "$tmp/elf-payload/HOLY/files"
tar -cf "$tmp/elf-bad.tar" -C "$tmp/elf-payload" HOLY DATA
lz4 -q "$tmp/elf-bad.tar" "$tmp/elf-bad.holy"
"$bin" verify "local:$tmp/elf-bad.holy" > "$tmp/out"
if "$bin" scan "local:$tmp/elf-bad.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'malformed ELF in payload' "$tmp/err"
mkdir "$tmp/fetched"
fetched=$("$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched")
test "$fetched" = "$tmp/fetched/$expected.holy"
cmp "$tmp/package.holy" "$fetched"
test "$(stat -c %a "$fetched")" = 600
test -z "$(find "$tmp/fetched" -name '.holy-tmp-*' -print)"
test "$("$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched")" = "$fetched"
printf 'damaged\n' > "$fetched"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'existing object differs' "$tmp/err"
grep -qx damaged "$fetched"
rm "$fetched"
ln -s "$tmp/package.holy" "$fetched"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'existing object differs' "$tmp/err"
test -L "$fetched"
rm "$fetched"
ln -s "$tmp/fetched" "$tmp/fetched-link"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched-link" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'output directory' "$tmp/err"
mkfifo "$tmp/pipe"
if "$bin" fetch "local:$tmp/pipe" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'input must be a regular file' "$tmp/err"
TMPDIR="$tmp" "$bin" fetch "local:$tmp/package.holy" --extract --output "$tmp/unpacked" > "$tmp/out"
cmp "$tmp/payload/HOLY/meta" "$tmp/unpacked/HOLY/meta"
cmp "$tmp/payload/DATA/usr/bin/hello" "$tmp/unpacked/DATA/usr/bin/hello"
test -z "$(find "$tmp" -maxdepth 1 -name 'holy-extract-*' -print)"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'changed payload: DATA/usr/' "$tmp/err"
chmod "$(stat -c %a "$tmp/payload/DATA/usr")" "$tmp/unpacked/DATA/usr"
chmod "$(stat -c %a "$tmp/payload/DATA/usr/bin")" "$tmp/unpacked/DATA/usr/bin"
"$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" > "$tmp/out"
grep -qx 'checked 3 payload objects' "$tmp/out"
TMPDIR="$tmp" "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" --json > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
grep -qx '{"schema":"holy-check-1","status":"pass","coverage":"local-payload","checked":3}' "$tmp/out"
test -z "$(find "$tmp" -maxdepth 1 -name 'holy-check-*' -print)"
mkdir "$tmp/empty-root"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/empty-root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test "$(wc -l < "$tmp/out")" -eq 4
grep -qx '{"schema":"holy-check-1","code":"missing-payload","severity":"error","status":"fail","path":"DATA/usr/"}' "$tmp/out"
grep -qx '{"schema":"holy-check-1","code":"missing-payload","severity":"error","status":"fail","path":"DATA/usr/bin/hello"}' "$tmp/out"
grep -qx '{"schema":"holy-check-1","status":"fail","coverage":"local-payload","checked":3,"findings":3}' "$tmp/out"
printf 'world\n' > "$tmp/unpacked/DATA/usr/bin/hello"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'changed payload: DATA/usr/bin/hello' "$tmp/err"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test "$(wc -l < "$tmp/out")" -eq 2
grep -qx '{"schema":"holy-check-1","code":"changed-payload","severity":"error","status":"fail","path":"DATA/usr/bin/hello"}' "$tmp/out"
grep -qx '{"schema":"holy-check-1","status":"fail","coverage":"local-payload","checked":3,"findings":1}' "$tmp/out"
rm "$tmp/unpacked/DATA/usr/bin/hello"
ln -s /etc/passwd "$tmp/unpacked/DATA/usr/bin/hello"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'changed payload: DATA/usr/bin/hello' "$tmp/err"
rm "$tmp/unpacked/DATA/usr/bin/hello"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx '{"schema":"holy-check-1","code":"missing-payload","severity":"error","status":"fail","path":"DATA/usr/bin/hello"}' "$tmp/out"
chmod 700 "$tmp/unpacked/DATA/usr"
if "$bin" check "local:$tmp/package.holy" --root "$tmp/unpacked/DATA" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test "$(wc -l < "$tmp/out")" -eq 3
grep -qx '{"schema":"holy-check-1","code":"changed-payload","severity":"error","status":"fail","path":"DATA/usr/"}' "$tmp/out"
grep -qx '{"schema":"holy-check-1","status":"fail","coverage":"local-payload","checked":3,"findings":2}' "$tmp/out"
if "$bin" fetch "local:$tmp/package.holy" --extract --output "$tmp/unpacked" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'create extraction directory' "$tmp/err"
cp "$tmp/payload/HOLY/meta" "$tmp/original-meta"
for variant in os arch libc noarch; do
    case "$variant" in
        os) sed 's/^os linux$/os solaris/' "$tmp/original-meta" > "$tmp/payload/HOLY/meta" ;;
        arch) sed 's/^arch x86_64$/arch x32/' "$tmp/original-meta" > "$tmp/payload/HOLY/meta" ;;
        libc) sed 's/^libc nolibc$/libc unknown/' "$tmp/original-meta" > "$tmp/payload/HOLY/meta" ;;
        noarch) sed -e 's/^arch x86_64$/arch noarch/' -e 's/^libc nolibc$/libc glibc/' \
            "$tmp/original-meta" > "$tmp/payload/HOLY/meta" ;;
    esac
    tar -cf "$tmp/metadata.tar" -C "$tmp/payload" HOLY DATA
    lz4 -q -f "$tmp/metadata.tar" "$tmp/metadata.holy"
    if "$bin" info "local:$tmp/metadata.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    grep -q "$variant" "$tmp/err"
done
cp "$tmp/original-meta" "$tmp/payload/HOLY/meta"
setfattr -n user.holy -v probe "$tmp/payload/DATA/usr/bin/hello"
tar --xattrs --format=pax -cf "$tmp/xattr.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/xattr.tar" "$tmp/xattr.holy"
if "$bin" verify "local:$tmp/xattr.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported payload xattrs' "$tmp/err"
"$bin" fetch "local:$tmp/xattr.holy" --output "$tmp/fetched" > "$tmp/out"
setfattr -x user.holy "$tmp/payload/DATA/usr/bin/hello"
setfacl -m u:12345:r-- "$tmp/payload/DATA/usr/bin/hello"
tar --acls --format=pax -cf "$tmp/acl.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/acl.tar" "$tmp/acl.holy"
if "$bin" verify "local:$tmp/acl.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported payload ACL' "$tmp/err"
setfacl -b "$tmp/payload/DATA/usr/bin/hello"
mkdir -p "$tmp/alias-payload/DATA/usr/bin"
cp -a "$tmp/payload/HOLY" "$tmp/alias-payload/HOLY"
cp "$tmp/payload/DATA/usr/bin/hello" "$tmp/alias-payload/DATA/usr/bin/hello"
ln -s usr/bin "$tmp/alias-payload/DATA/alias"
sed 's@file usr/bin/hello @file alias/evil @' \
    "$tmp/payload/HOLY/files" > "$tmp/alias-payload/HOLY/files"
printf 'symlink alias 777 root root %s %s 0 - none - - usr/bin\n' \
    "$uid" "$gid" >> "$tmp/alias-payload/HOLY/files"
tar -cf "$tmp/alias.tar" -C "$tmp/alias-payload" HOLY
tar -rf "$tmp/alias.tar" --no-recursion -C "$tmp/alias-payload" DATA DATA/alias DATA/usr DATA/usr/bin
tar -rf "$tmp/alias.tar" --transform='s@^DATA/usr/bin/hello$@DATA/alias/evil@' \
    -C "$tmp/alias-payload" DATA/usr/bin/hello
lz4 -q "$tmp/alias.tar" "$tmp/alias.holy"
"$bin" verify "local:$tmp/alias.holy" > "$tmp/out"
if "$bin" fetch "local:$tmp/alias.holy" --extract --output "$tmp/alias-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/alias-out"
cp -a "$tmp/alias-payload" "$tmp/file-parent-payload"
rm "$tmp/file-parent-payload/DATA/alias"
printf 'block\n' > "$tmp/file-parent-payload/DATA/alias"
parent_hash=$(sha256sum "$tmp/file-parent-payload/DATA/alias" | cut -d ' ' -f 1)
sed '/^symlink alias /d' "$tmp/file-parent-payload/HOLY/files" > "$tmp/parent-files"
printf 'file alias %s root root %s %s 6 %s none - -\n' \
    "$mode" "$uid" "$gid" "$parent_hash" >> "$tmp/parent-files"
mv "$tmp/parent-files" "$tmp/file-parent-payload/HOLY/files"
tar -cf "$tmp/file-parent.tar" -C "$tmp/file-parent-payload" HOLY
tar -rf "$tmp/file-parent.tar" --no-recursion -C "$tmp/file-parent-payload" \
    DATA DATA/alias DATA/usr DATA/usr/bin
tar -rf "$tmp/file-parent.tar" --transform='s@^DATA/usr/bin/hello$@DATA/alias/evil@' \
    -C "$tmp/file-parent-payload" DATA/usr/bin/hello
lz4 -q "$tmp/file-parent.tar" "$tmp/file-parent.holy"
"$bin" verify "local:$tmp/file-parent.holy" > "$tmp/out"
if "$bin" fetch "local:$tmp/file-parent.holy" --extract --output "$tmp/file-parent-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/file-parent-out"
: > "$tmp/payload/HOLY/extra"
tar -cf "$tmp/duplicate-extra.tar" -C "$tmp/payload" HOLY DATA
tar -rf "$tmp/duplicate-extra.tar" -C "$tmp/payload" HOLY/extra
lz4 -q "$tmp/duplicate-extra.tar" "$tmp/duplicate-extra.holy"
"$bin" verify "local:$tmp/duplicate-extra.holy" > "$tmp/out"
if "$bin" fetch "local:$tmp/duplicate-extra.holy" --extract --output "$tmp/duplicate-extra-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/duplicate-extra-out"
rm "$tmp/payload/HOLY/extra"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
chmod 4755 "$tmp/payload/DATA/usr/bin/hello"
sed "s@^file usr/bin/hello $mode @file usr/bin/hello 4755 @" \
    "$tmp/files-original" > "$tmp/payload/HOLY/files"
tar -cf "$tmp/setuid.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/setuid.tar" "$tmp/setuid.holy"
"$bin" fetch "local:$tmp/setuid.holy" --extract --output "$tmp/setuid-out" > "$tmp/out"
test "$(stat -c %a "$tmp/setuid-out/DATA/usr/bin/hello")" = 755
chmod "$mode" "$tmp/payload/DATA/usr/bin/hello"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
rm "$tmp/payload/HOLY/origin"
tar -cf "$tmp/missing-member.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/missing-member.tar" "$tmp/missing-member.holy"
if "$bin" info "local:$tmp/missing-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'missing HOLY/origin' "$tmp/err"
if TMPDIR="$tmp" "$bin" check "local:$tmp/missing-member.holy" --root "$tmp/unpacked/DATA" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx '{"schema":"holy-check-1","code":"invalid-package","severity":"error","status":"unknown"}' "$tmp/out"
test -z "$(find "$tmp" -maxdepth 1 -name 'holy-check-*' -print)"
: > "$tmp/payload/HOLY/origin"
tar -cf "$tmp/duplicate-member.tar" -C "$tmp/payload" HOLY DATA
tar -rf "$tmp/duplicate-member.tar" -C "$tmp/payload" HOLY/origin
lz4 -q "$tmp/duplicate-member.tar" "$tmp/duplicate-member.holy"
if "$bin" info "local:$tmp/duplicate-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'repeated HOLY/origin' "$tmp/err"
rm "$tmp/payload/HOLY/origin"
ln -s meta "$tmp/payload/HOLY/origin"
tar -cf "$tmp/symlink-member.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/symlink-member.tar" "$tmp/symlink-member.holy"
if "$bin" info "local:$tmp/symlink-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid or repeated HOLY/origin' "$tmp/err"
rm "$tmp/payload/HOLY/origin"
: > "$tmp/payload/HOLY/origin"
"$bin" verify "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 0 symlinks, 2 directories, 0 hardlinks' "$tmp/out"
printf 'world\n' > "$tmp/payload/DATA/usr/bin/hello"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/changed.holy"
if "$bin" verify "local:$tmp/changed.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'payload SHA-256 mismatch' "$tmp/err"
printf 'hello\n' > "$tmp/payload/DATA/usr/bin/hello"
tar -cf "$tmp/duplicate.tar" -C "$tmp/payload" HOLY DATA
tar -rf "$tmp/duplicate.tar" -C "$tmp/payload" DATA/usr/bin/hello
lz4 -q "$tmp/duplicate.tar" "$tmp/duplicate.holy"
if "$bin" verify "local:$tmp/duplicate.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'duplicate payload path' "$tmp/err"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
ln -s hello "$tmp/payload/DATA/usr/bin/link"
linkmode=$(stat -c %a "$tmp/payload/DATA/usr/bin/link")
printf 'symlink usr/bin/link %s root root %s %s 0 - none - - hello\n' \
    "$linkmode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/symlink.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/symlink.tar" "$tmp/symlink.holy"
"$bin" verify "local:$tmp/symlink.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 1 symlinks, 2 directories, 0 hardlinks' "$tmp/out"
"$bin" fetch "local:$tmp/symlink.holy" --extract --output "$tmp/symlink-out" > "$tmp/out"
test "$(readlink "$tmp/symlink-out/DATA/usr/bin/link")" = hello
chmod "$(stat -c %a "$tmp/payload/DATA/usr")" "$tmp/symlink-out/DATA/usr"
chmod "$(stat -c %a "$tmp/payload/DATA/usr/bin")" "$tmp/symlink-out/DATA/usr/bin"
"$bin" check "local:$tmp/symlink.holy" --root "$tmp/symlink-out/DATA" > "$tmp/out"
grep -qx 'checked 4 payload objects' "$tmp/out"
rm "$tmp/symlink-out/DATA/usr/bin/link"
ln -s wrong "$tmp/symlink-out/DATA/usr/bin/link"
if "$bin" check "local:$tmp/symlink.holy" --root "$tmp/symlink-out/DATA" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'changed payload: DATA/usr/bin/link' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/link"
ln -s /usr/bin/hello "$tmp/payload/DATA/usr/bin/link"
sed 's@symlink usr/bin/link \(.*\) hello$@symlink usr/bin/link \1 /usr/bin/hello@' \
    "$tmp/payload/HOLY/files" > "$tmp/absolute-files"
mv "$tmp/absolute-files" "$tmp/payload/HOLY/files"
tar -cf "$tmp/absolute.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/absolute.tar" "$tmp/absolute.holy"
if "$bin" fetch "local:$tmp/absolute.holy" --extract --output "$tmp/absolute-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/absolute-out"
rm "$tmp/payload/DATA/usr/bin/link"
ln -s ../../../escape "$tmp/payload/DATA/usr/bin/link"
tar -cf "$tmp/symlink.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/symlink.tar" "$tmp/unsafe-link.holy"
if "$bin" verify "local:$tmp/unsafe-link.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsafe symlink target' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/link"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
ln "$tmp/payload/DATA/usr/bin/hello" "$tmp/payload/DATA/usr/bin/hard"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
sed 's/^file \(.*\) none - -$/file \1 none - group1/' \
    "$tmp/files-original" > "$tmp/payload/HOLY/files"
printf 'hardlink usr/bin/hard %s root root %s %s 6 %s none - group1 usr/bin/hello\n' \
    "$mode" "$uid" "$gid" "$digest" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/hard.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/hard.tar" "$tmp/hard.holy"
"$bin" verify "local:$tmp/hard.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 0 symlinks, 2 directories, 1 hardlinks' "$tmp/out"
"$bin" fetch "local:$tmp/hard.holy" --extract --output "$tmp/hard-out" > "$tmp/out"
test "$(stat -c %i "$tmp/hard-out/DATA/usr/bin/hard")" = \
    "$(stat -c %i "$tmp/hard-out/DATA/usr/bin/hello")"
chmod "$(stat -c %a "$tmp/payload/DATA/usr")" "$tmp/hard-out/DATA/usr"
chmod "$(stat -c %a "$tmp/payload/DATA/usr/bin")" "$tmp/hard-out/DATA/usr/bin"
"$bin" check "local:$tmp/hard.holy" --root "$tmp/hard-out/DATA" > "$tmp/out"
grep -qx 'checked 4 payload objects' "$tmp/out"
rm "$tmp/hard-out/DATA/usr/bin/hard"
cp "$tmp/hard-out/DATA/usr/bin/hello" "$tmp/hard-out/DATA/usr/bin/hard"
if "$bin" check "local:$tmp/hard.holy" --root "$tmp/hard-out/DATA" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'changed payload: DATA/usr/bin/hard' "$tmp/err"
sed 's/group1 usr\/bin\/hello$/group2 usr\/bin\/hello/' \
    "$tmp/payload/HOLY/files" > "$tmp/files-mismatch"
mv "$tmp/files-mismatch" "$tmp/payload/HOLY/files"
tar -cf "$tmp/hard.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/hard.tar" "$tmp/hard-mismatch.holy"
if "$bin" verify "local:$tmp/hard-mismatch.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'hardlink group mismatch' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/hard"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
sed '/^dir usr\/bin /d' "$tmp/payload/HOLY/files" > "$tmp/files-without-dir"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
mv "$tmp/files-without-dir" "$tmp/payload/HOLY/files"
tar -cf "$tmp/omitted-dir.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/omitted-dir.tar" "$tmp/omitted-dir.holy"
if "$bin" verify "local:$tmp/omitted-dir.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unlisted payload object' "$tmp/err"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
chmod 700 "$tmp/payload/DATA/usr/bin"
tar -cf "$tmp/changed-dir.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/changed-dir.tar" "$tmp/changed-dir.holy"
if "$bin" verify "local:$tmp/changed-dir.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'payload or attributes mismatch' "$tmp/err"
chmod "$dmode" "$tmp/payload/DATA/usr/bin"
cp "$tmp/package.holy" "$tmp/broken.holy"
printf 'not a frame' > "$tmp/broken.holy"
if "$bin" info "local:$tmp/broken.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'expected LZ4 frame' "$tmp/err"
sed 's/format holy-package-1/format future-format/' "$tmp/payload/HOLY/meta" > "$tmp/meta"
mv "$tmp/meta" "$tmp/payload/HOLY/meta"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/future.holy"
if "$bin" info "local:$tmp/future.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported format' "$tmp/err"
sed 's/format future-format/format holy-package-1\nrequires-feature unknown-extension/' \
    "$tmp/payload/HOLY/meta" > "$tmp/meta"
mv "$tmp/meta" "$tmp/payload/HOLY/meta"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/feature.holy"
if "$bin" info "local:$tmp/feature.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported feature' "$tmp/err"
tar -cf "$tmp/traversal.tar" --transform='s@^DATA/usr/bin/hello$@DATA/../../escape@' \
    -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/traversal.tar" "$tmp/traversal.holy"
if "$bin" info "local:$tmp/traversal.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsafe or unexpected archive path' "$tmp/err"
if "$bin" fetch "local:$tmp/traversal.holy" --extract --output "$tmp/traversal-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/traversal-out"
printf 'package fixtures passed\n'
