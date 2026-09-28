#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/root" "$tmp/repo" "$tmp/tree/HOLY" "$tmp/tree/DATA/usr/share"
build() {
    name=$1
    required=$2
    kind=${3:-package}
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tmp/tree/HOLY/meta"
    if test "$name" = or-root; then
        printf 'x-version-family deb\n' >> "$tmp/tree/HOLY/meta"
    fi
    for field in files deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
    if test -n "$required"; then
        printf 'require dep-1 %s %s %s any any any - %s metadata\n' \
            "$name" "$kind" "$required" "$required" > "$tmp/tree/HOLY/deps"
    fi
    rm -f "$tmp/tree/DATA/usr/share/"*
    printf '%s\n' "$name" > "$tmp/tree/DATA/usr/share/$name"
    "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tmp/tree/HOLY/files"
    "$bin" pack "$tmp/tree" --output "$tmp/repo/$name.holy" > "$tmp/out"
}
build root dep
build dep leaf
build leaf ''
build file-root /usr/share/file-provider file
build file-provider ''
build unrelated ''
build foreign-root foreign-dep
build reuse-root foreign-dep
build foreign-dep ''
build foreign-unused ''
build provider-root external-package
build external-package ''
build external-file-root /usr/share/external-file file
build external-file ''
build auto-root auto-child
build auto-child auto-leaf
build auto-leaf ''
build auto-file-root /usr/share/auto-file file
build auto-file ''
build missing-root absent-package
build or-root 'or-first@ge@2|or-second@any@-' package-or
build or-first ''
build or-second ''
mkdir -p "$tmp/other-repo"
mv "$tmp/repo/foreign-dep.holy" "$tmp/other-repo/foreign-dep.holy"
mv "$tmp/repo/foreign-unused.holy" "$tmp/other-repo/foreign-unused.holy"
mv "$tmp/repo/external-package.holy" "$tmp/other-repo/external-package.holy"
mv "$tmp/repo/external-file.holy" "$tmp/other-repo/external-file.holy"
mv "$tmp/repo/auto-child.holy" "$tmp/other-repo/auto-child.holy"
mv "$tmp/repo/auto-leaf.holy" "$tmp/other-repo/auto-leaf.holy"
mv "$tmp/repo/auto-file.holy" "$tmp/other-repo/auto-file.holy"
mv "$tmp/repo/or-second.holy" "$tmp/other-repo/or-second.holy"
case "$(uname -m)" in
    x86_64)
        arch=x86_64
        printf '.global _start\n_start:\n mov $60, %%rax\n xor %%rdi, %%rdi\n syscall\n' > "$tmp/helper.s"
        ;;
    i?86)
        arch=x86
        printf '.global _start\n_start:\n mov $1, %%eax\n xor %%ebx, %%ebx\n int $0x80\n' > "$tmp/helper.s"
        ;;
    *) arch= ;;
esac
if test -n "$arch"; then
    "${CC:-cc}" -nostdlib -static -o "$tmp/helper" "$tmp/helper.s"
    rm -rf "$tmp/tree/DATA"
    mkdir -p "$tmp/tree/DATA/usr/bin"
    printf 'format holy-package-1\nname helper\nversion 1\nrelease 1\nos linux\narch %s\nlibc nolibc\n' "$arch" > "$tmp/tree/HOLY/meta"
    for field in files deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
    cp "$tmp/helper" "$tmp/tree/DATA/usr/bin/closure-helper"
    "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tmp/tree/HOLY/files"
    "$bin" pack "$tmp/tree" --output "$tmp/repo/helper.holy" > "$tmp/out"
    rm -rf "$tmp/tree/DATA"
    mkdir -p "$tmp/tree/DATA/usr/bin"
    printf 'format holy-package-1\nname script\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tmp/tree/HOLY/meta"
    for field in files deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
    printf '#!/usr/bin/closure-helper\n' > "$tmp/tree/DATA/usr/bin/closure-script"
    chmod 755 "$tmp/tree/DATA/usr/bin/closure-script"
    "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tmp/tree/HOLY/files"
    "$bin" pack "$tmp/tree" --output "$tmp/repo/script.holy" > "$tmp/out"
    cat > "$tmp/foo.c" <<'C'
int foo(void) { return 2; }
C
    cat > "$tmp/good.map" <<'MAP'
GOOD_1 { global: foo; };
MAP
    cat > "$tmp/bad.map" <<'MAP'
BAD_1 { global: foo; };
MAP
    printf 'extern int foo(void); int consumer(void) { return foo(); }\n' > "$tmp/consumer.c"
    "${CC:-cc}" -shared -fPIC -o "$tmp/libgood.so" "$tmp/foo.c" \
        -Wl,-soname,libchoice.so.1 -Wl,--version-script="$tmp/good.map" \
        -Wl,--no-as-needed -lc
    "${CC:-cc}" -shared -fPIC -o "$tmp/libbad.so" "$tmp/foo.c" \
        -Wl,-soname,libchoice.so.1 -Wl,--version-script="$tmp/bad.map" \
        -Wl,--no-as-needed -lc
    "${CC:-cc}" -shared -fPIC -o "$tmp/libconsumer.so" "$tmp/consumer.c" \
        -L"$tmp" -lgood -Wl,--no-as-needed -lc
    for name in good bad consumer; do
        rm -rf "$tmp/tree/DATA"
        mkdir -p "$tmp/tree/DATA/usr/lib/holy/${arch}-linux-gnu"
        printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch %s\nlibc glibc\n' \
            "$name" "$arch" > "$tmp/tree/HOLY/meta"
        for field in files deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
        cp "$tmp/lib$name.so" "$tmp/tree/DATA/usr/lib/holy/${arch}-linux-gnu/lib$name.so"
        "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
        mv "$tmp/files" "$tmp/tree/HOLY/files"
        "$bin" pack "$tmp/tree" --output "$tmp/repo/$name.holy" > "$tmp/out"
    done
fi
if test -n "$arch"; then
    mv "$tmp/repo/helper.holy" "$tmp/other-repo/helper.holy"
fi
"$bin" repo index "$tmp/repo" > "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
"$bin" repo index "$tmp/other-repo" > "$tmp/out"
"$bin" repo seal "$tmp/other-repo" > "$tmp/out"
index=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
other_index=$(sed -n 's/^sha256 //p' "$tmp/other-repo/current")
"$bin" db init --root "$tmp/root" > "$tmp/out"
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\n[source other]\ntype holy-http\nurl https://other.example/holy/\n' > "$tmp/config"
"$bin" source plan --config "$tmp/config" --root "$tmp/root" > "$tmp/plan"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/plan" --sha256 "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" source list --root "$tmp/root" > "$tmp/out"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/out")
other_id=$(sed -n 's/^source \([0-9a-f]*\) "other" active$/\1/p' "$tmp/out")
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$index" "$source_id" > "$tmp/repo/mirror-origin"
printf 'format holy-mirror-1\nurl "https://other.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$other_index" "$other_id" > "$tmp/other-repo/mirror-origin"
"$bin" source catalog bind fixture "$tmp/repo" --root "$tmp/root" > "$tmp/out"
"$bin" source catalog bind other "$tmp/other-repo" --root "$tmp/root" > "$tmp/out"
if "$bin" add fixture:missing-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 4
fi
test ! -e "$tmp/root/usr/share/missing-root"
if "$bin" add fixture:foreign-root --candidate other:foreign-dep \
    --candidate other:foreign-unused --root "$tmp/root" \
    > "$tmp/out" 2> "$tmp/err" < /dev/null; then exit 1; else test "$?" -eq 3; fi
test ! -e "$tmp/root/usr/share/foreign-root"
"$bin" add fixture:foreign-root --candidate other:foreign-dep \
    --candidate other:foreign-unused --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
foreign_hash=$(sha256sum "$tmp/other-repo/foreign-dep.holy" | cut -d ' ' -f 1)
test -f "$tmp/root/usr/share/foreign-root"
test -f "$tmp/root/usr/share/foreign-dep"
test ! -e "$tmp/root/usr/share/foreign-unused"
grep -q "$other_id" "$tmp/root/var/lib/holypkg/installed/$foreign_hash/source"
"$bin" db check --all --root "$tmp/root" > "$tmp/out"
mkdir -p "$tmp/third-repo"
cp "$tmp/other-repo/auto-child.holy" "$tmp/third-repo/auto-child.holy"
"$bin" repo index "$tmp/third-repo" > "$tmp/out"
"$bin" repo seal "$tmp/third-repo" > "$tmp/out"
third_index=$(sed -n 's/^sha256 //p' "$tmp/third-repo/current")
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\n[source other]\ntype holy-http\nurl https://other.example/holy/\n[source third]\ntype holy-http\nurl https://third.example/holy/\n' > "$tmp/three-sources"
"$bin" source plan --config "$tmp/three-sources" --root "$tmp/root" > "$tmp/plan"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/plan" --sha256 "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" source list --root "$tmp/root" > "$tmp/out"
third_id=$(sed -n 's/^source \([0-9a-f]*\) "third" active$/\1/p' "$tmp/out")
test -n "$third_id"
printf 'format holy-mirror-1\nurl "https://third.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$third_index" "$third_id" > "$tmp/third-repo/mirror-origin"
"$bin" source catalog bind third "$tmp/third-repo" --root "$tmp/root" > "$tmp/out"
if "$bin" add fixture:auto-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 3
fi
grep -q 'provider package:auto-child available from other' "$tmp/err"
grep -q 'provider package:auto-child available from third' "$tmp/err"
grep -q 'decision-required' "$tmp/err"
test ! -e "$tmp/root/usr/share/auto-root"
for target in choice-root answers-root; do
    mkdir -p "$tmp/$target"
    "$bin" db init --root "$tmp/$target" > "$tmp/out"
    "$bin" source plan --config "$tmp/three-sources" --root "$tmp/$target" > "$tmp/choice-plan"
    choice_plan=$(sha256sum "$tmp/choice-plan" | cut -d ' ' -f 1)
    "$bin" source apply "$tmp/choice-plan" --sha256 "$choice_plan" --root "$tmp/$target" > "$tmp/out"
    for source in fixture other third; do
        case "$source" in
            fixture) catalog=$tmp/repo ;;
            other) catalog=$tmp/other-repo ;;
            third) catalog=$tmp/third-repo ;;
        esac
        "$bin" source catalog bind "$source" "$catalog" --root "$tmp/$target" > "$tmp/out"
    done
done
python3 - "$bin" "$tmp/choice-root" <<'PY'
import os
import pty
import subprocess
import sys

master, slave = pty.openpty()
process = subprocess.Popen([sys.argv[1], "add", "fixture:auto-root",
                            "--root", sys.argv[2], "--yes"], stdin=slave,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)
os.close(slave)
os.write(master, b"other\n")
stdout, stderr = process.communicate(timeout=30)
os.close(master)
assert process.returncode == 0, (process.returncode, stdout, stderr)
assert "Select source for package:auto-child" in stderr
PY
test -f "$tmp/choice-root/usr/share/auto-root"
test -f "$tmp/choice-root/usr/share/auto-child"
"$bin" db check --all --root "$tmp/choice-root" > "$tmp/out"
auto_root_hash=$(sha256sum "$tmp/repo/auto-root.holy" | cut -d ' ' -f 1)
printf 'format holy-answers-1\nsource %s dep-1 other\nsource %s dep-1 third\n' \
    "$auto_root_hash" "$auto_root_hash" > "$tmp/duplicate-answers"
if "$bin" add fixture:auto-root --root "$tmp/answers-root" --yes --noninteractive \
    --answers "$tmp/duplicate-answers" > "$tmp/out" 2> "$tmp/err"; then exit 1
else test "$?" -eq 2; fi
printf 'format holy-answers-1\nsource %s dep-1 absent\n' \
    "$auto_root_hash" > "$tmp/stale-answers"
if "$bin" add fixture:auto-root --root "$tmp/answers-root" --yes --noninteractive \
    --answers "$tmp/stale-answers" > "$tmp/out" 2> "$tmp/err"; then exit 1
else test "$?" -eq 3; fi
test ! -e "$tmp/answers-root/usr/share/auto-root"
printf 'format holy-answers-1\nsource %s dep-1 other' "$auto_root_hash" > "$tmp/answers"
if ! "$bin" add fixture:auto-root --root "$tmp/answers-root" --yes --noninteractive \
    --answers "$tmp/answers" > "$tmp/out" 2> "$tmp/err"; then
    cat "$tmp/err" >&2
    exit 1
fi
test -f "$tmp/answers-root/usr/share/auto-root"
test -f "$tmp/answers-root/usr/share/auto-child"
"$bin" db check --all --root "$tmp/answers-root" > "$tmp/out"
"$bin" source plan --config "$tmp/config" --root "$tmp/root" > "$tmp/plan"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/plan" --sha256 "$plan" --root "$tmp/root" > "$tmp/out"
if "$bin" add fixture:auto-root --root "$tmp/root" \
    > "$tmp/out" 2> "$tmp/err" < /dev/null; then
    exit 1
else
    test "$?" -eq 3
fi
test ! -e "$tmp/root/usr/share/auto-root"
"$bin" add fixture:auto-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/auto-child"
test -f "$tmp/root/usr/share/auto-leaf"
"$bin" add fixture:auto-file-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/auto-file"
"$bin" add fixture:or-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/or-root"
test -f "$tmp/root/usr/share/or-second"
test ! -e "$tmp/root/usr/share/or-first"
"$bin" db check --all --root "$tmp/root" > "$tmp/out"
"$bin" add fixture:provider-root --candidate-provider other:package:external-package \
    --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/external-package"
if "$bin" add fixture:external-file-root \
    --candidate-provider other:file:/usr/share/missing-provider \
    --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 4
fi
"$bin" add fixture:external-file-root \
    --candidate-provider other:file:/usr/share/external-file \
    --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/external-file"
"$bin" db check --all --root "$tmp/root" > "$tmp/out"
if test -n "$arch"; then
    grep -q '"GOOD_1"' "$tmp/repo/index"
    grep -q '"BAD_1"' "$tmp/repo/index"
    bad=$(sha256sum "$tmp/repo/bad.holy" | cut -d ' ' -f 1)
    good=$(sha256sum "$tmp/repo/good.holy" | cut -d ' ' -f 1)
    cp "$tmp/repo/bad.holy" "$tmp/bad.saved"
    printf 'corrupt\n' > "$tmp/repo/bad.holy"
    if "$bin" add fixture:consumer --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    if grep -q 'invalid or stale repository index' "$tmp/err"; then cat "$tmp/err"; exit 1; fi
    test -f "$tmp/root/var/cache/holypkg/objects/sha256/$good.holy"
    test ! -e "$tmp/root/var/cache/holypkg/objects/sha256/$bad.holy"
    cp "$tmp/bad.saved" "$tmp/repo/bad.holy"
fi
cp "$tmp/repo/dep.holy" "$tmp/dep.saved"
printf 'corrupt\n' > "$tmp/repo/dep.holy"
if "$bin" add fixture:root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/root/usr/share/root"
cp "$tmp/dep.saved" "$tmp/repo/dep.holy"
unrelated=$(sha256sum "$tmp/repo/unrelated.holy" | cut -d ' ' -f 1)
printf 'corrupt\n' > "$tmp/repo/unrelated.holy"
"$bin" add fixture:root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
for name in root dep leaf; do
    test -f "$tmp/root/usr/share/$name"
    digest=$(sha256sum "$tmp/repo/$name.holy" | cut -d ' ' -f 1)
    test -f "$tmp/root/var/cache/holypkg/objects/sha256/$digest.holy"
done
test ! -e "$tmp/root/var/cache/holypkg/objects/sha256/$unrelated.holy"
"$bin" db check --all --root "$tmp/root" > "$tmp/out"
"$bin" add fixture:file-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/file-root"
test -f "$tmp/root/usr/share/file-provider"
if test -n "$arch"; then
    "$bin" add fixture:script --candidate-provider other:command:closure-helper \
        --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
    test -x "$tmp/root/usr/bin/closure-helper"
    test -x "$tmp/root/usr/bin/closure-script"
fi
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\n' > "$tmp/fixture-only"
"$bin" source plan --config "$tmp/fixture-only" --root "$tmp/root" > "$tmp/plan"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/plan" --sha256 "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" add fixture:reuse-root --root "$tmp/root" --yes > "$tmp/out" 2> "$tmp/err"
test -f "$tmp/root/usr/share/reuse-root"
"$bin" db check --all --root "$tmp/root" > "$tmp/out"
