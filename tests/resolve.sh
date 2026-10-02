#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA"
for part in files deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$part"
done
build() {
    name=$1 version=$2
    cat > "$tmp/payload/HOLY/meta" <<EOF
format holy-package-1
name $name
version $version
release 1
os linux
arch noarch
libc nolibc
EOF
    tar -cf "$tmp/$name-$version.tar" -C "$tmp/payload" HOLY DATA
    lz4 -q "$tmp/$name-$version.tar" "$tmp/$name-$version.holy"
}
printf 'require b-1 root package b any any any - b metadata\n' > "$tmp/payload/HOLY/deps"
build root 1
: > "$tmp/payload/HOLY/deps"
build b 1
build b 2
build unused 1
root_hash=$(sha256sum "$tmp/root-1.holy")
root_hash=${root_hash%% *}
b_hash=$(sha256sum "$tmp/b-1.holy")
b_hash=${b_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/unused-1.holy" > "$tmp/out"
grep -qx "selected $root_hash" "$tmp/out"
grep -qx "selected $b_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$root_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b_hash\"}" "$tmp/out"
grep -Fqx '{"schema":"holy-local-solve-1","type":"summary","count":2}' "$tmp/out"
mkdir "$tmp/repo"
cp "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" "$tmp/repo/"
"$bin" repo index "$tmp/repo" > "$tmp/out"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-catalog"}' "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
generation=$(sha256sum "$tmp/repo/index")
generation=${generation%% *}
"$bin" repo solve "$tmp/repo" root --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$root_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":2,\"generation\":\"$generation\"}" "$tmp/out"
"$bin" repo solve "$tmp/repo" root > "$tmp/out"
grep -qx "generation $generation" "$tmp/out"
if "$bin" repo solve "$tmp/repo" absent --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"unavailable-artifact"}' "$tmp/out"
b2_hash=$(sha256sum "$tmp/b-2.holy")
b2_hash=${b2_hash%% *}
mkdir "$tmp/repo-choice"
cp "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" "$tmp/repo-choice/"
"$bin" repo index "$tmp/repo-choice" > "$tmp/out"
"$bin" repo seal "$tmp/repo-choice" > "$tmp/out"
choice_generation=$(sha256sum "$tmp/repo-choice/index")
choice_generation=${choice_generation%% *}
if test "$#" -ge 2; then
    api=$2
    "$api" - "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" > "$tmp/record"
    "$api" - "$tmp/root-1.holy" "$tmp/unused-1.holy" "$tmp/b-1.holy" > "$tmp/reordered"
    cmp "$tmp/record" "$tmp/reordered"
    grep -qx 'format holy-resolution-1' "$tmp/record"
    grep -qx 'scope artifact-candidates' "$tmp/record"
    grep -Fqx "edge \"$root_hash\" \"b-1\" \"$b_hash\" \"-\" \"package\" \"b\"" "$tmp/record"
    test "$(wc -l < "$tmp/record")" -eq 6
    "$api" "b-1=$b2_hash" "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" > "$tmp/chosen"
    grep -Fqx "edge \"$root_hash\" \"b-1\" \"$b2_hash\" \"-\" \"package\" \"b\"" "$tmp/chosen"
    if "$api" - "$tmp/root-1.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
    test ! -s "$tmp/record"
    "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" > "$tmp/record"
    "$api" --set "$tmp/root-1.holy" "$tmp/unused-1.holy" "$tmp/b-1.holy" > "$tmp/reordered"
    cmp "$tmp/record" "$tmp/reordered"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 3
    if "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
    test ! -s "$tmp/record"
    printf 'require missing-1 unused package missing any any any - missing metadata\n' > "$tmp/payload/HOLY/deps"
    build unused 2
    "$api" - "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-2.holy" > "$tmp/record"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 2
    if "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-2.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
    test ! -s "$tmp/record"
    printf 'require y-1 x package y any any any - y metadata\n' > "$tmp/payload/HOLY/deps"
    build x 1
    printf 'require x-1 y package x any any any - x metadata\n' > "$tmp/payload/HOLY/deps"
    build y 1
    "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/x-1.holy" "$tmp/y-1.holy" > "$tmp/record"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 4
    test "$(grep -c '^edge ' "$tmp/record")" -eq 3
    : > "$tmp/payload/HOLY/deps"
fi
if "$bin" repo solve "$tmp/repo-choice" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
"$bin" repo solve "$tmp/repo-choice" root --choose "b-1=$b2_hash" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b2_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":2,\"generation\":\"$choice_generation\"}" "$tmp/out"
if grep -Fq "\"sha256\":\"$b_hash\"" "$tmp/out"; then exit 1; fi
if "$bin" repo solve "$tmp/repo-choice" root --choose "b-1=$root_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
# a choice naming an artifact that does not provide the requirement is refused, and the
# report names the candidates that do
grep -Fq '"type":"choice"' "$tmp/out"
grep -Fq "\"requirement\":\"b-1\"" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
if "$bin" repo solve "$tmp/repo-choice" root --choose broken --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
printf 'corrupt\n' > "$tmp/repo/unused-1.holy"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-catalog"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
cp "$tmp/unused-1.holy" "$tmp/repo/unused-1.holy"
printf 'require c-1 b package c any any any - c metadata\n' > "$tmp/payload/HOLY/deps"
build b 3
: > "$tmp/payload/HOLY/deps"
build c 1
c_hash=$(sha256sum "$tmp/c-1.holy")
c_hash=${c_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" "local:$tmp/c-1.holy" > "$tmp/out"
grep -qx "selected $root_hash" "$tmp/out"
grep -qx "selected $c_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 3
b3_hash=$(sha256sum "$tmp/b-3.holy")
b3_hash=${b3_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-3.holy" "local:$tmp/c-1.holy" --choose "b-1=$b3_hash" > "$tmp/out"
grep -qx "selected $c_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 3
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-3.holy" --choose "b-1=$b3_hash" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict","requirement":"c-1"}' "$tmp/out"
printf 'require d-1 b package d any any any - d metadata\n' > "$tmp/payload/HOLY/deps"
build b 4
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" "local:$tmp/b-4.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict"}' "$tmp/out"
: > "$tmp/payload/HOLY/deps"
printf 'require root-1 b package root any any any - root metadata\n' > "$tmp/payload/HOLY/deps"
build b 5
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-5.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
: > "$tmp/payload/HOLY/deps"
printf 'provide package b noarch nolibc - metadata\n' > "$tmp/payload/HOLY/provides"
build alias 1
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/alias-1.holy" > "$tmp/out"
alias_hash=$(sha256sum "$tmp/alias-1.holy")
alias_hash=${alias_hash%% *}
grep -qx "selected $alias_hash" "$tmp/out"
: > "$tmp/payload/HOLY/provides"
if "$bin" solve "local:$tmp/root-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
grep -q 'unresolved requirement b-1' "$tmp/err"
if "$bin" solve "local:$tmp/root-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict","requirement":"b-1"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -qx "choice b-1 consumer=$root_hash candidates=2" "$tmp/out"
grep -qx "candidate $b_hash slot b linux noarch nolibc version 1 release 1" "$tmp/out"
grep -qx "candidate $b2_hash slot b linux noarch nolibc version 2 release 1" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 3
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
python3 - "$tmp/out" "$root_hash" "$b_hash" "$b2_hash" <<'PYCHOICE'
import json, pathlib, sys
events = [json.loads(x) for x in pathlib.Path(sys.argv[1]).read_text().splitlines()]
choice = next(x for x in events if x['type'] == 'choice')
assert choice['consumer'] == sys.argv[2] and choice['requirement'] == 'b-1'
assert choice['candidates'] == [
    {"sha256": sys.argv[3], "slot": {"name": "b", "os": "linux", "arch": "noarch",
                                     "libc": "nolibc"}, "version": "1", "release": "1"},
    {"sha256": sys.argv[4], "slot": {"name": "b", "os": "linux", "arch": "noarch",
                                     "libc": "nolibc"}, "version": "2", "release": "1"}]
PYCHOICE
# a requirement one artifact fills names no candidate, since nothing is in the way
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" > "$tmp/out"
if grep -q '^choice ' "$tmp/out"; then exit 1; fi
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --choose "b-1=$b2_hash" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b2_hash\"}" "$tmp/out"
if grep -Fq "\"sha256\":\"$b_hash\"" "$tmp/out"; then exit 1; fi
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --choose "b-1=$b_hash" > "$tmp/out"
grep -qx "selected $b_hash" "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose "b-1=$root_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose "other=$b_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose 'bad' --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-1.holy" bad --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'require b-1 root soname b any any any - b metadata\n' > "$tmp/payload/HOLY/deps"
build root 2
cp "$tmp/root-2.holy" "$tmp/repo/"
"$bin" repo index "$tmp/repo" > "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-2.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-2.holy" "local:$tmp/b-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict","requirement":"b-1"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
printf 'require b-1 root package b any any eq 1 b metadata\n' > "$tmp/payload/HOLY/deps"
build root 3
if "$bin" solve "local:$tmp/root-3.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/deps"
printf 'postinstall /bin/sh script\n' > "$tmp/payload/HOLY/hooks"
build root 4
"$bin" solve "local:$tmp/root-4.holy" > "$tmp/out"
grep -q '^selected ' "$tmp/out"
: > "$tmp/payload/HOLY/hooks"
printf 'patch binary\n' > "$tmp/payload/HOLY/transform"
build root 5
"$bin" solve "local:$tmp/root-5.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
: > "$tmp/payload/HOLY/transform"
sed -i 's/arch noarch/arch x86_64/' "$tmp/payload/HOLY/meta"
tar -cf "$tmp/foreign.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/foreign.tar" "$tmp/foreign.holy"
"$bin" solve "local:$tmp/foreign.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
mkdir -p "$tmp/payload/DATA/usr/share/holy"
printf 'fixture\n' > "$tmp/payload/DATA/usr/share/holy/provider.txt"
ln -s provider.txt "$tmp/payload/DATA/usr/share/holy/provider-link.txt"
ln "$tmp/payload/DATA/usr/share/holy/provider.txt" "$tmp/payload/DATA/usr/share/holy/provider-hard.txt"
"$bin" manifest generate "$tmp/payload" --output "$tmp/file-manifest" > "$tmp/out"
mv "$tmp/file-manifest" "$tmp/payload/HOLY/files"
build file-provider 1
rm "$tmp/file-provider-1.holy"
"$bin" pack "$tmp/payload" --output "$tmp/file-provider-1.holy" > "$tmp/out"
rm -r "$tmp/payload/DATA/usr"
: > "$tmp/payload/HOLY/files"
printf 'provide file /usr/share/holy/provider.txt any any 1 metadata\n' > "$tmp/payload/HOLY/provides"
build false-provider 1
: > "$tmp/payload/HOLY/provides"
printf 'require file-1 file-root file /usr/share/holy/provider.txt any any any - file metadata\n' > "$tmp/payload/HOLY/deps"
printf 'require file-link file-root file /usr/share/holy/provider-link.txt any any any - file metadata\n' >> "$tmp/payload/HOLY/deps"
printf 'require file-hard file-root file /usr/share/holy/provider-hard.txt any any any - file metadata\n' >> "$tmp/payload/HOLY/deps"
build file-root 1
: > "$tmp/payload/HOLY/deps"
file_provider_hash=$(sha256sum "$tmp/file-provider-1.holy")
file_provider_hash=${file_provider_hash%% *}
file_root_hash=$(sha256sum "$tmp/file-root-1.holy")
file_root_hash=${file_root_hash%% *}
"$bin" solve "local:$tmp/file-root-1.holy" "local:$tmp/file-provider-1.holy" > "$tmp/out"
grep -qx "selected $file_root_hash" "$tmp/out"
grep -qx "selected $file_provider_hash" "$tmp/out"
if "$bin" solve "local:$tmp/file-root-1.holy" "local:$tmp/false-provider-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
mkdir "$tmp/file-rootfs"
"$bin" db init --root "$tmp/file-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/file-root-1.holy" --root "$tmp/file-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/file-provider-1.holy" --root "$tmp/file-rootfs" > "$tmp/out"
"$bin" db plan-set "$file_root_hash" "$file_provider_hash" --root "$tmp/file-rootfs" > "$tmp/out"
file_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#file_plan}" -eq 64
"$bin" db apply-set "$file_plan" "$file_root_hash" "$file_provider_hash" --root "$tmp/file-rootfs" > "$tmp/out"
grep -Fqx "edge \"$file_root_hash\" \"file-1\" \"$file_provider_hash\" \"-\" \"file\" \"/usr/share/holy/provider.txt\"" "$tmp/file-rootfs/var/lib/holypkg/installed/$file_root_hash/graph"
grep -Fqx "edge \"$file_root_hash\" \"file-link\" \"$file_provider_hash\" \"-\" \"file\" \"/usr/share/holy/provider-link.txt\"" "$tmp/file-rootfs/var/lib/holypkg/installed/$file_root_hash/graph"
grep -Fqx "edge \"$file_root_hash\" \"file-hard\" \"$file_provider_hash\" \"-\" \"file\" \"/usr/share/holy/provider-hard.txt\"" "$tmp/file-rootfs/var/lib/holypkg/installed/$file_root_hash/graph"
"$bin" db check --all --root "$tmp/file-rootfs" > "$tmp/out"
"$bin" orphan --root "$tmp/file-rootfs" --json > "$tmp/out"
grep -q '"installed":2,"explicit":1,"reachable":2,"orphans":0' "$tmp/out"
if "$bin" db rm "$file_provider_hash" --root "$tmp/file-rootfs" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
test -f "$tmp/file-rootfs/usr/share/holy/provider.txt"
cat > "$tmp/helper.s" <<'EOF'
.global _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
EOF
as -o "$tmp/helper.o" "$tmp/helper.s"
ld -static -o "$tmp/helper" "$tmp/helper.o"
mkdir -p "$tmp/payload/DATA/usr/bin"
cp "$tmp/helper" "$tmp/payload/DATA/usr/bin/helper"
ln -s helper "$tmp/payload/DATA/usr/bin/helper-link"
ln "$tmp/payload/DATA/usr/bin/helper" "$tmp/payload/DATA/usr/bin/helper-hard"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name command-provider
version 1
release 1
os linux
arch x86_64
libc nolibc
EOF
"$bin" manifest generate "$tmp/payload" --output "$tmp/command-manifest" > "$tmp/out"
mv "$tmp/command-manifest" "$tmp/payload/HOLY/files"
"$bin" pack "$tmp/payload" --output "$tmp/command-provider.holy" > "$tmp/out"
rm -r "$tmp/payload/DATA/usr"
: > "$tmp/payload/HOLY/files"
printf 'provide command helper any any 1 metadata\n' > "$tmp/payload/HOLY/provides"
build false-command 1
: > "$tmp/payload/HOLY/provides"
mkdir -p "$tmp/payload/DATA/usr/bin"
printf 'not executable\n' > "$tmp/payload/DATA/usr/bin/helper"
"$bin" manifest generate "$tmp/payload" --output "$tmp/nonexec-manifest" > "$tmp/out"
mv "$tmp/nonexec-manifest" "$tmp/payload/HOLY/files"
build nonexec-command 1
rm -r "$tmp/payload/DATA/usr"
: > "$tmp/payload/HOLY/files"
printf 'require helper-1 command-root command helper any any any - helper metadata\n' > "$tmp/payload/HOLY/deps"
printf 'require helper-link command-root command helper-link any any any - helper metadata\n' >> "$tmp/payload/HOLY/deps"
printf 'require helper-hard command-root command helper-hard any any any - helper metadata\n' >> "$tmp/payload/HOLY/deps"
build command-root 1
: > "$tmp/payload/HOLY/deps"
command_provider_hash=$(sha256sum "$tmp/command-provider.holy")
command_provider_hash=${command_provider_hash%% *}
command_root_hash=$(sha256sum "$tmp/command-root-1.holy")
command_root_hash=${command_root_hash%% *}
"$bin" solve "local:$tmp/command-root-1.holy" "local:$tmp/command-provider.holy" > "$tmp/out"
grep -qx "selected $command_provider_hash" "$tmp/out"
if "$bin" solve "local:$tmp/command-root-1.holy" "local:$tmp/false-command-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" solve "local:$tmp/command-root-1.holy" "local:$tmp/nonexec-command-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
mkdir "$tmp/command-rootfs"
"$bin" db init --root "$tmp/command-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/command-root-1.holy" --root "$tmp/command-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/command-provider.holy" --root "$tmp/command-rootfs" > "$tmp/out"
"$bin" db plan-set "$command_root_hash" "$command_provider_hash" --root "$tmp/command-rootfs" > "$tmp/out"
command_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#command_plan}" -eq 64
"$bin" db apply-set "$command_plan" "$command_root_hash" "$command_provider_hash" --root "$tmp/command-rootfs" > "$tmp/out"
grep -Fqx "edge \"$command_root_hash\" \"helper-1\" \"$command_provider_hash\" \"-\" \"command\" \"helper\"" "$tmp/command-rootfs/var/lib/holypkg/installed/$command_root_hash/graph"
grep -Fqx "edge \"$command_root_hash\" \"helper-link\" \"$command_provider_hash\" \"-\" \"command\" \"helper-link\"" "$tmp/command-rootfs/var/lib/holypkg/installed/$command_root_hash/graph"
grep -Fqx "edge \"$command_root_hash\" \"helper-hard\" \"$command_provider_hash\" \"-\" \"command\" \"helper-hard\"" "$tmp/command-rootfs/var/lib/holypkg/installed/$command_root_hash/graph"
"$bin" db check --all --root "$tmp/command-rootfs" > "$tmp/out"
if "$bin" db rm "$command_provider_hash" --root "$tmp/command-rootfs" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
printf 'broken\n' > "$tmp/broken.holy"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/broken.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'require foreign-1 foreign-root foreign "option A | option B" any any any - "option A | option B" upstream\n' > "$tmp/payload/HOLY/deps"
build foreign-root 1
: > "$tmp/payload/HOLY/deps"
if "$bin" solve "local:$tmp/foreign-root-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"unsupported-requirement","requirement":"foreign-1"}' "$tmp/out"
"$bin" solve "local:$tmp/b-1.holy" "local:$tmp/foreign-root-1.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
printf 'require soname-1 soname-root soname libc.musl-x86_64.so.1 x86_64 musl any - libc.musl-x86_64.so.1 metadata\n' > "$tmp/payload/HOLY/deps"
build soname-root 1
: > "$tmp/payload/HOLY/deps"
printf 'provide soname libc.musl-x86_64.so.1 x86_64 musl - forged\n' > "$tmp/payload/HOLY/provides"
build false-soname 1
: > "$tmp/payload/HOLY/provides"
if "$bin" solve "local:$tmp/soname-root-1.holy" "local:$tmp/false-soname-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
mkdir -p "$tmp/payload/DATA/usr/lib"
cat > "$tmp/soname.s" <<'EOF'
.global holy_fixture
holy_fixture:
    mov $42, %eax
    ret
EOF
as -o "$tmp/soname.o" "$tmp/soname.s"
ld -shared -soname libc.musl-x86_64.so.1 -o "$tmp/payload/DATA/usr/lib/libc.musl-x86_64.so.1" "$tmp/soname.o"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name soname-provider
version 1
release 1
os linux
arch x86_64
libc musl
EOF
"$bin" manifest generate "$tmp/payload" --output "$tmp/soname-manifest" > "$tmp/out"
mv "$tmp/soname-manifest" "$tmp/payload/HOLY/files"
"$bin" pack "$tmp/payload" --output "$tmp/soname-provider.holy" > "$tmp/out"
soname_hash=$(sha256sum "$tmp/soname-provider.holy")
soname_hash=${soname_hash%% *}
soname_root_hash=$(sha256sum "$tmp/soname-root-1.holy")
soname_root_hash=${soname_root_hash%% *}
"$bin" solve "local:$tmp/soname-root-1.holy" "local:$tmp/soname-provider.holy" > "$tmp/out"
grep -qx "selected $soname_hash" "$tmp/out"
mkdir "$tmp/soname-repo"
cp "$tmp/soname-provider.holy" "$tmp/soname-repo/"
"$bin" repo index "$tmp/soname-repo" > "$tmp/out"
grep -Fqx "soname $soname_hash \"libc.musl-x86_64.so.1\" \"x86_64\" \"musl\" \"usr/lib/libc.musl-x86_64.so.1\"" "$tmp/soname-repo/index"
cp "$tmp/soname-repo/index" "$tmp/soname-index"
sed '/^soname /d' "$tmp/soname-index" > "$tmp/soname-repo/index"
if "$bin" repo seal "$tmp/soname-repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cp "$tmp/soname-index" "$tmp/soname-repo/index"
"$bin" repo seal "$tmp/soname-repo" > "$tmp/out"
"$bin" repo providers "$tmp/soname-repo" soname libc.musl-x86_64.so.1 > "$tmp/out"
grep -qx 'listed 1 candidates' "$tmp/out"
if test "$#" -ge 2; then
    "$api" - "$tmp/soname-root-1.holy" "$tmp/soname-provider.holy" > "$tmp/record"
    grep -Fqx "edge \"$soname_root_hash\" \"soname-1\" \"$soname_hash\" \"-\" \"soname\" \"libc.musl-x86_64.so.1\"" "$tmp/record"
fi
mkdir "$tmp/soname-rootfs"
"$bin" db init --root "$tmp/soname-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/soname-root-1.holy" --root "$tmp/soname-rootfs" > "$tmp/out"
"$bin" cache stage "local:$tmp/soname-provider.holy" --root "$tmp/soname-rootfs" > "$tmp/out"
"$bin" db plan-set "$soname_root_hash" "$soname_hash" --root "$tmp/soname-rootfs" > "$tmp/out"
soname_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#soname_plan}" -eq 64
"$bin" db apply-set "$soname_plan" "$soname_root_hash" "$soname_hash" --root "$tmp/soname-rootfs" > "$tmp/out"
grep -Fqx "edge \"$soname_root_hash\" \"soname-1\" \"$soname_hash\" \"-\" \"soname\" \"libc.musl-x86_64.so.1\"" "$tmp/soname-rootfs/var/lib/holypkg/installed/$soname_root_hash/graph"
"$bin" db check --all --root "$tmp/soname-rootfs" > "$tmp/out"
rm "$tmp/soname-rootfs/var/cache/holypkg/objects/sha256/$soname_root_hash.holy"
rm -r "$tmp/payload/DATA/usr"
: > "$tmp/payload/HOLY/files"
printf 'require soname-2 soname-consumer soname libc.musl-x86_64.so.1 x86_64 musl any - libc.musl-x86_64.so.1 metadata\n' > "$tmp/payload/HOLY/deps"
build soname-consumer 1
soname_consumer_hash=$(sha256sum "$tmp/soname-consumer-1.holy")
soname_consumer_hash=${soname_consumer_hash%% *}
"$bin" cache stage "local:$tmp/soname-consumer-1.holy" --root "$tmp/soname-rootfs" > "$tmp/out"
"$bin" db plan-set "$soname_consumer_hash" --root "$tmp/soname-rootfs" > "$tmp/out"
soname_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#soname_plan}" -eq 64
"$bin" db apply-set "$soname_plan" "$soname_consumer_hash" --root "$tmp/soname-rootfs" > "$tmp/out"
grep -Fqx "edge \"$soname_consumer_hash\" \"soname-2\" \"$soname_hash\" \"-\" \"soname\" \"libc.musl-x86_64.so.1\"" "$tmp/soname-rootfs/var/lib/holypkg/installed/$soname_consumer_hash/graph"
"$bin" db check --all --root "$tmp/soname-rootfs" > "$tmp/out"
printf 'require soname-wrong soname-wrong-root soname libc.musl-x86_64.so.1 x86 musl any - libc.musl-x86_64.so.1 metadata\n' > "$tmp/payload/HOLY/deps"
build soname-wrong-root 1
soname_wrong_hash=$(sha256sum "$tmp/soname-wrong-root-1.holy")
soname_wrong_hash=${soname_wrong_hash%% *}
"$bin" cache stage "local:$tmp/soname-wrong-root-1.holy" --root "$tmp/soname-rootfs" > "$tmp/out"
if "$bin" db plan-set "$soname_wrong_hash" --root "$tmp/soname-rootfs" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" db rm "$soname_hash" --root "$tmp/soname-rootfs" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
printf 'local resolver fixtures passed\n'
