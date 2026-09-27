#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tree="$tmp/tree"
new() {
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch %s\nlibc glibc\n' "$1" "${2:-x86_64}" > "$tree/HOLY/meta"
    for part in deps provides hooks origin transform; do : > "$tree/HOLY/$part"; done
}
pack() {
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/pack.out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$1.holy" >> "$tmp/pack.out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
printf '#include <stdio.h>\nint main(void) { return puts("probe") < 0; }\n' > "$tmp/probe.c"
gcc -o "$tmp/probe" "$tmp/probe.c"
loader=$("$bin" elf "$tmp/probe" | sed -n 's/^interpreter //p')
case "$loader" in /*) ;; *) exit 6 ;; esac
new runtime
mkdir -p "$tree/DATA$(dirname "$loader")" "$tree/DATA/usr/lib/holy/x86_64-linux-gnu"
cp -L "$loader" "$tree/DATA$loader"
cp -L "$(gcc -print-file-name=libc.so.6)" "$tree/DATA/usr/lib/holy/x86_64-linux-gnu/libc.so.6"
pack runtime
new runtime-noexec
mkdir -p "$tree/DATA$(dirname "$loader")" "$tree/DATA/usr/lib/holy/x86_64-linux-gnu"
cp -L "$loader" "$tree/DATA$loader"
chmod 644 "$tree/DATA$loader"
cp -L "$(gcc -print-file-name=libc.so.6)" "$tree/DATA/usr/lib/holy/x86_64-linux-gnu/libc.so.6"
pack runtime-noexec
new probe
cp "$tmp/probe" "$tree/DATA/usr/bin/probe"
pack probe
"$bin" solve "local:$tmp/probe.holy" "local:$tmp/runtime.holy" --json > "$tmp/out"
grep -Fq '"type":"summary","count":2' "$tmp/out"
if "$bin" solve "local:$tmp/probe.holy" "local:$tmp/runtime-noexec.holy" \
    --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -q '"code":"unknown-interpreter-context"' "$tmp/out"
mkdir "$tmp/repository"
cp "$tmp/probe.holy" "$tmp/runtime.holy" "$tmp/repository/"
"$bin" repo index "$tmp/repository" > "$tmp/out"
"$bin" repo seal "$tmp/repository" > "$tmp/out"
"$bin" repo solve "$tmp/repository" probe --json > "$tmp/out"
grep -Fq '"type":"summary","count":2,' "$tmp/out"

printf 'extern int puts(const char *); int holy_api(void) { return puts("fixture") < 0; }\n' > "$tmp/library.c"
printf 'HOLY_1 { global: holy_api; local: *; };\n' > "$tmp/library.map"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/library.map" \
    -o "$tmp/good.so" "$tmp/library.c"
printf 'extern int holy_api(void); extern int optional(void) __attribute__((weak)); int main(void) { return holy_api() || (optional && optional()); }\n' > "$tmp/consumer.c"
gcc -o "$tmp/consumer" "$tmp/consumer.c" "$tmp/good.so"
ln -s good.so "$tmp/libholyfixture.so.1"
LD_LIBRARY_PATH="$tmp" "$tmp/consumer" > "$tmp/run.out"
grep -qx fixture "$tmp/run.out"
new consumer
cp "$tmp/consumer" "$tree/DATA/usr/bin/consumer"
pack consumer
new good
cp "$tmp/good.so" "$tree/DATA/usr/bin/library.so"
pack good
new alternate
cp "$tmp/good.so" "$tree/DATA/usr/bin/library.so"
pack alternate
printf 'extern int puts(const char *); int wrong_api(void) { return puts("wrong") < 0; }\n' > "$tmp/wrong.c"
printf 'HOLY_1 { global: wrong_api; local: *; };\n' > "$tmp/wrong.map"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/wrong.map" \
    -o "$tmp/wrong.so" "$tmp/wrong.c"
new wrong-symbol
cp "$tmp/wrong.so" "$tree/DATA/usr/bin/library.so"
pack wrong-symbol
printf 'HOLY_2 { global: holy_api; local: *; };\n' > "$tmp/wrong.map"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/wrong.map" \
    -o "$tmp/wrong.so" "$tmp/library.c"
new wrong-version
cp "$tmp/wrong.so" "$tree/DATA/usr/bin/library.so"
pack wrong-version
printf 'extern int puts(const char *); int holy_api(void) { return puts("pie"); } int main(void) { return 0; }\n' > "$tmp/pie.c"
gcc -fPIE -pie -rdynamic -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/library.map" \
    -o "$tmp/pie" "$tmp/pie.c"
new wrong-pie
cp "$tmp/pie" "$tree/DATA/usr/bin/library.so"
pack wrong-pie

printf '.global puts\nputs: ret\n' | as --32 -o "$tmp/libc32.o"
ld -m elf_i386 -shared -soname libc.so.6 -o "$tmp/libc32.so" "$tmp/libc32.o"
gcc -m32 -nostdlib -shared -fPIC -Wl,-soname,libholyfixture.so.1 \
    -Wl,--version-script="$tmp/library.map" -o "$tmp/library32.so" "$tmp/library.c" "$tmp/libc32.so"
new wrong-arch x86
cp "$tmp/library32.so" "$tree/DATA/usr/bin/library.so"
pack wrong-arch
"$bin" solve "local:$tmp/consumer.holy" "local:$tmp/good.holy" \
    "local:$tmp/wrong-symbol.holy" "local:$tmp/wrong-version.holy" \
    "local:$tmp/wrong-arch.holy" "local:$tmp/runtime.holy" --json > "$tmp/out"
python3 - "$tmp/out" "$(hash good)" "$(hash runtime)" "$(hash consumer)" <<'PY'
import json, pathlib, sys
events = [json.loads(x) for x in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert {x['sha256'] for x in events if x['type'] == 'selected'} == set(sys.argv[2:])
edges = [x for x in events if x['type'] == 'elf-edge']
assert edges and not any(x['target'] == 'optional' for x in edges)
assert any(x['kind'] == 'soname' and x['target'] == 'libholyfixture.so.1' and x['providers'] == [sys.argv[2]] for x in edges)
PY
for bad in wrong-symbol wrong-version wrong-arch wrong-pie; do
    if "$bin" solve "local:$tmp/consumer.holy" "local:$tmp/$bad.holy" \
        "local:$tmp/runtime.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
    grep -q '"code":"dependency-conflict"' "$tmp/out"
done
if "$bin" solve "local:$tmp/consumer.holy" "local:$tmp/good.holy" \
    "local:$tmp/alternate.holy" "local:$tmp/runtime.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
id=$(python3 - "$tmp/out" <<'PY'
import json, pathlib, sys
events = [json.loads(x) for x in pathlib.Path(sys.argv[1]).read_text().splitlines()]
edges = [x for x in events if x['type'] == 'elf-edge' and x['target'] == 'libholyfixture.so.1']
assert len(edges) == 1 and len(edges[0]['providers']) == 2
print(edges[0]['id'])
PY
)
"$bin" solve "local:$tmp/consumer.holy" "local:$tmp/alternate.holy" \
    "local:$tmp/good.holy" "local:$tmp/runtime.holy" --choose "$id=$(hash good)" --json > "$tmp/out"
grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash good)\"" "$tmp/out"
if grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash alternate)\"" "$tmp/out"; then exit 1; fi
if "$bin" solve "local:$tmp/consumer.holy" "local:$tmp/wrong-symbol.holy" \
    "local:$tmp/good.holy" "local:$tmp/runtime.holy" --choose "$id=$(hash wrong-symbol)" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
if "$bin" solve "local:$tmp/consumer.holy" "local:$tmp/good.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -q '"code":"unknown-interpreter-context"' "$tmp/out"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -o "$tmp/unversioned.so" "$tmp/library.c"
gcc -o "$tmp/unversioned-consumer" "$tmp/consumer.c" "$tmp/unversioned.so"
new unversioned
cp "$tmp/unversioned.so" "$tree/DATA/usr/bin/library.so"
pack unversioned
new unversioned-consumer
cp "$tmp/unversioned-consumer" "$tree/DATA/usr/bin/consumer"
pack unversioned-consumer
gcc -shared -fPIC -Wl,-soname,libalien.so.1 -o "$tmp/alien.so" "$tmp/library.c"
new alien
cp "$tmp/alien.so" "$tree/DATA/usr/bin/library.so"
printf 'provide soname libholyfixture.so.1 x86_64 glibc - metadata\n' > "$tree/HOLY/provides"
pack alien
"$bin" solve "local:$tmp/unversioned-consumer.holy" "local:$tmp/unversioned.holy" \
    "local:$tmp/wrong-symbol.holy" "local:$tmp/alien.holy" "local:$tmp/runtime.holy" --json > "$tmp/out"
grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash unversioned)\"" "$tmp/out"
if grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash alien)\"" "$tmp/out"; then exit 1; fi
id=$(python3 - "$tmp/out" <<'PY'
import json, pathlib, sys
events = [json.loads(x) for x in pathlib.Path(sys.argv[1]).read_text().splitlines()]
print(next(x['id'] for x in events if x['type'] == 'elf-edge' and x['kind'] == 'soname' and x['target'] == 'libholyfixture.so.1'))
PY
)
if "$bin" solve "local:$tmp/unversioned-consumer.holy" "local:$tmp/wrong-symbol.holy" \
    "local:$tmp/alien.holy" "local:$tmp/runtime.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -q '"code":"unknown-symbol-scope"' "$tmp/out"
if "$bin" solve "local:$tmp/unversioned-consumer.holy" "local:$tmp/wrong-symbol.holy" \
    "local:$tmp/unversioned.holy" "local:$tmp/runtime.holy" --choose "$id=$(hash wrong-symbol)" \
    --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
cat > "$tmp/compat.c" <<'EOF'
extern int puts(const char *);
int old_api(void) { return puts("old-version") < 0; }
int new_api(void) { return puts("new-version") < 0; }
__asm__(".symver old_api,holy_api@HOLY_1");
__asm__(".symver new_api,holy_api@@HOLY_2");
EOF
printf 'HOLY_1 {}; HOLY_2 { global: holy_api; local: *; } HOLY_1;\n' > "$tmp/compat.map"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/compat.map" \
    -o "$tmp/compat.so" "$tmp/compat.c"
new compatibility
cp "$tmp/compat.so" "$tree/DATA/usr/bin/library.so"
pack compatibility
"$bin" solve "local:$tmp/consumer.holy" "local:$tmp/compatibility.holy" \
    "local:$tmp/runtime.holy" --json > "$tmp/out"
grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash compatibility)\"" "$tmp/out"
mkdir "$tmp/compat-runtime"
cp "$tmp/compat.so" "$tmp/compat-runtime/libholyfixture.so.1"
LD_LIBRARY_PATH="$tmp/compat-runtime" "$tmp/consumer" > "$tmp/run.out"
grep -qx old-version "$tmp/run.out"
sed 's/int holy_api/__attribute__((weak)) int holy_api/' "$tmp/library.c" > "$tmp/weak.c"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/library.map" \
    -o "$tmp/weak.so" "$tmp/weak.c"
new weak-definition
cp "$tmp/weak.so" "$tree/DATA/usr/bin/library.so"
pack weak-definition
"$bin" solve "local:$tmp/consumer.holy" "local:$tmp/weak-definition.holy" \
    "local:$tmp/runtime.holy" --json > "$tmp/out"
grep -Fq "\"type\":\"selected\",\"sha256\":\"$(hash weak-definition)\"" "$tmp/out"
gcc -shared -fPIC -o "$tmp/no-soname.so" "$tmp/library.c"
gcc -o "$tmp/path-consumer" "$tmp/consumer.c" "$tmp/no-soname.so"
new path-consumer
cp "$tmp/path-consumer" "$tree/DATA/usr/bin/consumer"
pack path-consumer
if "$bin" solve "local:$tmp/path-consumer.holy" "local:$tmp/runtime.holy" \
    --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -q 'DT_NEEDED paths require a launch context' "$tmp/err"
if test "${HOLY_TEST_STATIC_CHROOT:-0}" = 1; then
    "$bin" elf "$bin" > "$tmp/out"
    grep -qx 'runtime nolibc' "$tmp/out"
    command -v doas >/dev/null && doas -n true || exit 6
    mkdir -p "$tmp/root/usr/bin" "$tmp/root/tmp" "$tmp/root/input"
    cp "$bin" "$tmp/root/usr/bin/holypkg"
    cp "$tmp/consumer.holy" "$tmp/good.holy" "$tmp/runtime.holy" "$tmp/root/input/"
    doas -n chroot --userspec="$(id -u):$(id -g)" "$tmp/root" \
        /usr/bin/holypkg solve local:/input/consumer.holy local:/input/good.holy \
        local:/input/runtime.holy --json > "$tmp/out"
    grep -Fq '"type":"summary","count":3' "$tmp/out"
    test ! -e "$tmp/root/lib" && test ! -e "$tmp/root/usr/lib"
    printf 'libc-free ELF resolver fixture passed\n'
fi
printf 'ELF resolver fixtures passed\n'
