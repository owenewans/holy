#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tree="$tmp/tree"
new() {
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch %s\nlibc %s\n' \
        "$1" "$2" "${3:-noarch}" "${4:-nolibc}" > "$tree/HOLY/meta"
    if [ "$2" != "-" ]; then printf 'x-version-family %s\n' "${5:-holy}" >> "$tree/HOLY/meta"; fi
    for part in deps provides hooks origin transform; do : > "$tree/HOLY/$part"; done
}
pack() {
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/pack.out"
    mv "$tmp/files" "$tree/HOLY/files"
    rm -f "$tmp/$1.holy"
    "$bin" pack "$tree" --output "$tmp/$1.holy" >> "$tmp/pack.out"
}
# the loader and its libc, so a script provider resolves its interpreter edge
printf '#include <stdio.h>\nint main(void) { return puts("probe") < 0; }\n' > "$tmp/probe.c"
gcc -o "$tmp/probe" "$tmp/probe.c"
loader=$("$bin" elf "$tmp/probe" | sed -n 's/^interpreter //p')
case "$loader" in /*) ;; *) exit 6 ;; esac
new shell-runtime 1.0 x86_64 glibc holy
mkdir -p "$tree/DATA$(dirname "$loader")" "$tree/DATA/usr/lib/shell-runtime" "$tree/DATA/bin"
cp -L "$loader" "$tree/DATA$loader"
cp -L "$(gcc -print-file-name=libc.so.6)" "$tree/DATA$(dirname "$loader")/libc.so.6"
cp "$tmp/probe" "$tree/DATA/bin/sh"
pack shell-runtime

# a package whose payload owns a program, so a versioned command requirement has
# something to resolve against
printf '#!/bin/sh\necho fixture\n' > "$tmp/hello"
chmod 755 "$tmp/hello"
new tool-new 2.5 noarch nolibc holy
cp "$tmp/hello" "$tree/DATA/usr/bin/hello"
pack tool-new
new tool-old 1.0 noarch nolibc holy
cp "$tmp/hello" "$tree/DATA/usr/bin/hello"
pack tool-old
new tool-unversioned 9.9 noarch nolibc -
cp "$tmp/hello" "$tree/DATA/usr/bin/hello"
pack tool-unversioned

# a consumer that requires the program at a minimum version, which only a provider of
# that version satisfies
new tool-user 1.0 noarch nolibc holy
printf 'require command-req tool-user command hello any any ge 2.0 command:hello literal\n' \
    > "$tree/HOLY/deps"
printf 'data\n' > "$tree/DATA/usr/share/tool-user-value"
pack tool-user
new_sha=$(sha256sum "$tmp/tool-new.holy" | cut -d ' ' -f 1)

"$bin" solve "local:$tmp/tool-user.holy" "local:$tmp/tool-new.holy" "local:$tmp/shell-runtime.holy" \
    > "$tmp/out" 2> "$tmp/err"
grep -qx "selected $new_sha" "$tmp/out"
# the provider that is too old does not satisfy the requirement, and neither does one
# whose version family the comparison cannot use
for other in tool-old tool-unversioned; do
    status=0
    "$bin" solve "local:$tmp/tool-user.holy" "local:$tmp/$other.holy" \
        "local:$tmp/shell-runtime.holy" > "$tmp/out" 2> "$tmp/err" || status=$?
    test "$status" -eq 4
    grep -q "command-req" "$tmp/err"
done
# both providers together still resolve against the one that satisfies it
"$bin" solve "local:$tmp/tool-user.holy" "local:$tmp/tool-old.holy" "local:$tmp/tool-new.holy" \
    "local:$tmp/shell-runtime.holy" > "$tmp/out" 2> "$tmp/err"
grep -qx "selected $new_sha" "$tmp/out"

# an unversioned command requirement still matches any provider that owns the program
new tool-plain 1.0 noarch nolibc holy
printf 'require command-plain tool-plain command hello any any any - command:hello literal\n' \
    > "$tree/HOLY/deps"
printf 'data\n' > "$tree/DATA/usr/share/tool-plain-value"
pack tool-plain
old_sha=$(sha256sum "$tmp/tool-old.holy" | cut -d ' ' -f 1)
"$bin" solve "local:$tmp/tool-plain.holy" "local:$tmp/tool-old.holy" \
    "local:$tmp/shell-runtime.holy" > "$tmp/out" 2> "$tmp/err"
grep -qx "selected $old_sha" "$tmp/out"

# the chosen edge reaches the installed graph, so removing the provider is refused
mkdir "$tmp/root"
"$bin" db init --root "$tmp/root" > "$tmp/out"
for artifact in tool-new tool-user shell-runtime; do
    "$bin" cache stage "local:$tmp/$artifact.holy" --root "$tmp/root" > "$tmp/out"
done
user_sha=$(sha256sum "$tmp/tool-user.holy" | cut -d ' ' -f 1)
runtime_sha=$(sha256sum "$tmp/shell-runtime.holy" | cut -d ' ' -f 1)
"$bin" db plan-set "$user_sha" "$new_sha" "$runtime_sha" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"
plan=$(sed -n 's/.*sha256 \([0-9a-f]*\) read-only/\1/p' "$tmp/out")
"$bin" db apply-set "$plan" "$user_sha" "$new_sha" "$runtime_sha" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"
"$bin" db check "$user_sha" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"
status=0
"$bin" db rm "$new_sha" --root "$tmp/root" > "$tmp/out" 2> "$tmp/err" || status=$?
test "$status" -eq 3
grep -q "still required by" "$tmp/err"
grep -q "$user_sha" "$tmp/err"
echo "versioned command requirement fixtures passed"
