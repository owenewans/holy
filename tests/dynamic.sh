#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
runtime=/usr/lib/holy/x86_64-linux-gnu
loader=$runtime/ld-linux-x86-64.so.2
libc=$runtime/libc.so.6
library=$runtime/libholyfixture.so.1
mkdir -p "$root$runtime" "$root/usr/bin" "$root/usr/lib64" "$root/tmp" \
    "$root/usr/share/licenses/glibc" "$root/usr/share/doc/glibc"
ln -s usr/lib64 "$root/lib64"
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then got=0; else got=$?; fi
    test "$got" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
repair_pkg() {
    if test "${HOLY_TEST_STATIC_RECOVERY:-0}" = 1; then
        doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/holypkg "$@" --root /
    else
        "$bin" "$@" --root "$root"
    fi
}
new() {
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch x86_64\nlibc %s\n' "$1" "${2:-glibc}" > "$tree/HOLY/meta"
    for name in deps provides hooks origin transform; do : > "$tree/HOLY/$name"; done
}
pack() {
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$1.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$1.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
printf '#include <stdio.h>\nint holy_fixture(void) { return puts("dynamic-probe") < 0; }\n' > "$tmp/library.c"
printf 'extern int holy_fixture(void); int main(void) { return holy_fixture(); }\n' > "$tmp/main.c"
printf 'HOLY_1 { global: holy_fixture; local: *; };\n' > "$tmp/map"
gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/map" -o "$tmp/library.so" "$tmp/library.c"
gcc -o "$tmp/probe" "$tmp/main.c" "$tmp/library.so"
host_loader=$(patchelf --print-interpreter "$tmp/probe")
"$bin" db init --root "$root" > "$tmp/out"
new runtime
if test -n "${GLIBC_PACKAGE:-}"; then
    cp "$GLIBC_PACKAGE" "$tmp/runtime.holy"
    "$bin" cache stage "local:$tmp/runtime.holy" --root "$root" > "$tmp/out"
else
mkdir -p "$tree/DATA$runtime" "$tree/DATA/usr/lib64"
cp -L "$host_loader" "$tree/DATA$loader"
cp -L "$(gcc -print-file-name=libc.so.6)" "$tree/DATA$libc"
sha256sum "$tree/DATA$loader" "$tree/DATA$libc" > "$tree/HOLY/origin"
patchelf --set-interpreter "$loader" --replace-needed ld-linux-x86-64.so.2 "$loader" "$tree/DATA$libc"
ln -s ../lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$tree/DATA/usr/lib64/ld-linux-x86-64.so.2"
pack runtime
fi
new library
mkdir -p "$tree/DATA$runtime"
cp "$tmp/library.so" "$tree/DATA$library"
sha256sum "$tmp/library.so" > "$tree/HOLY/origin"
patchelf --replace-needed libc.so.6 "$libc" "$tree/DATA$library"
pack library
new probe
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/probe"
sha256sum "$tmp/probe" > "$tree/HOLY/origin"
patchelf --set-interpreter "$loader" --replace-needed libc.so.6 "$libc" --replace-needed libholyfixture.so.1 "$library" "$tree/DATA/usr/bin/probe"
pack probe
probe=$(hash probe) provider=$(hash library) runtime_hash=$(hash runtime)
expect 0 "$bin" db plan-set "$probe" "$provider" "$runtime_hash" --root "$root"
grep -q 'needed-path' "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
expect 0 "$bin" db apply-set "$plan" "$probe" "$provider" "$runtime_hash" --root "$root"
expect 0 "$bin" db check --all --root "$root"
new unresolved-soname
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/unresolved-soname"
patchelf --set-interpreter "$loader" --replace-needed libc.so.6 "$libc" \
    "$tree/DATA/usr/bin/unresolved-soname"
pack unresolved-soname
expect 3 "$bin" db plan-set "$(hash unresolved-soname)" --root "$root"
grep -q 'unknown-loader-search' "$tmp/err"
new soname-probe
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/soname-probe"
patchelf --set-interpreter "$loader" --set-rpath "$runtime" \
    --replace-needed libc.so.6 "$libc" \
    "$tree/DATA/usr/bin/soname-probe"
pack soname-probe
soname_probe=$(hash soname-probe)
expect 0 "$bin" db plan-set "$soname_probe" --root "$root"
soname_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
expect 0 "$bin" db apply-set "$soname_plan" "$soname_probe" --root "$root"
expect 0 "$bin" db check "$soname_probe" --root "$root" --json
grep -q '"state":"pass"' "$tmp/out"
cp -p "$root$library" "$tmp/soname-library.saved"
printf corrupt > "$root$library"
expect 4 "$bin" db check "$soname_probe" --root "$root" --json
grep -q '"code":"broken-provider"' "$tmp/out"
cp -p "$tmp/soname-library.saved" "$root$library"
expect 0 "$bin" db check "$soname_probe" --root "$root"
new soname-probe
sed -i 's/^version 1$/version 2/' "$tree/HOLY/meta"
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/soname-probe"
patchelf --set-interpreter "$loader" --set-rpath /usr/lib/nowhere \
    --replace-needed libc.so.6 "$libc" "$tree/DATA/usr/bin/soname-probe"
pack soname-probe-wrong
expect 3 "$bin" db plan-update "$soname_probe" "$(hash soname-probe-wrong)" --root "$root"
new soname-probe
sed -i 's/^version 1$/version 2/' "$tree/HOLY/meta"
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/soname-probe"
patchelf --set-interpreter "$loader" --set-rpath "$runtime" \
    --replace-needed libc.so.6 "$libc" "$tree/DATA/usr/bin/soname-probe"
pack soname-probe-next
soname_next=$(hash soname-probe-next)
expect 0 "$bin" db plan-update "$soname_probe" "$soname_next" --root "$root"
soname_update=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
expect 0 "$bin" db apply-update "$soname_update" "$soname_probe" "$soname_next" --root "$root"
expect 0 "$bin" db check "$soname_next" --root "$root"
expect 0 "$bin" db rm "$soname_next" --root "$root"
printf 'int alias_fixture(void) { return 0; }\n' > "$tmp/alias-library.c"
printf 'extern int alias_fixture(void); int main(void) { return alias_fixture(); }\n' > "$tmp/alias-main.c"
gcc -shared -fPIC -Wl,-soname,libaliasfixture.so.1 -o "$tmp/libalias.so" "$tmp/alias-library.c" \
    -Wl,--no-as-needed -lc
gcc -o "$tmp/alias-probe" "$tmp/alias-main.c" "$tmp/libalias.so"
new alias-provider
mkdir -p "$tree/DATA$runtime"
cp "$tmp/libalias.so" "$tree/DATA$runtime/libaliasfixture.so.1.2"
patchelf --replace-needed libc.so.6 "$libc" "$tree/DATA$runtime/libaliasfixture.so.1.2"
ln -s libaliasfixture.so.1.2 "$tree/DATA$runtime/libaliasfixture.so.1"
pack alias-provider
alias_provider=$(hash alias-provider)
new alias-probe
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/alias-probe" "$tree/DATA/usr/bin/alias-probe"
patchelf --set-interpreter "$loader" --set-rpath "$runtime" \
    --replace-needed libc.so.6 "$libc" "$tree/DATA/usr/bin/alias-probe"
pack alias-probe
alias_probe=$(hash alias-probe)
expect 0 "$bin" db plan-set "$alias_probe" "$alias_provider" --root "$root"
alias_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
expect 0 "$bin" db apply-set "$alias_plan" "$alias_probe" "$alias_provider" --root "$root"
expect 0 "$bin" db check "$alias_probe" --root "$root"
rm "$root$runtime/libaliasfixture.so.1"
ln -s missing.so "$root$runtime/libaliasfixture.so.1"
expect 4 "$bin" db check "$alias_probe" --root "$root" --json
grep -q '"code":"broken-provider"' "$tmp/out"
rm "$root$runtime/libaliasfixture.so.1"
ln -s libaliasfixture.so.1.2 "$root$runtime/libaliasfixture.so.1"
expect 0 "$bin" db check "$alias_probe" --root "$root"
expect 0 "$bin" db rm "$alias_probe" --root "$root"
expect 0 "$bin" db rm "$alias_provider" --root "$root"
test "$(readlink "$root/usr/lib64/ld-linux-x86-64.so.2")" = ../lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2
cp -a "$root" "$tmp/broken-libc"
expect 3 "$bin" db rm "$runtime_hash" --root "$tmp/broken-libc"
expect 0 "$bin" db rm "$runtime_hash" --accept-broken --root "$tmp/broken-libc"
test ! -e "$tmp/broken-libc$libc"
test ! -e "$tmp/broken-libc$loader"
expect 4 "$bin" db check --all --root "$tmp/broken-libc" --json
grep -q '"code":"broken-provider"' "$tmp/out"
expect 0 "$bin" db plan-set "$runtime_hash" --root "$tmp/broken-libc"
broken_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#broken_plan}" -eq 64
expect 0 "$bin" db apply-set "$broken_plan" "$runtime_hash" --root "$tmp/broken-libc"
expect 0 "$bin" db check --all --root "$tmp/broken-libc"
if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
    doas -n chroot --userspec="$(id -u):$(id -g)" "$tmp/broken-libc" /usr/bin/probe > "$tmp/recovered-run"
    grep -qx dynamic-probe "$tmp/recovered-run"
fi
for variant in compatible broken; do
    if test "$variant" = compatible; then symbol=holy_fixture; else symbol=wrong_fixture; fi
    printf '#include <stdio.h>\nint %s(void) { return puts("updated-probe") < 0; }\n' "$symbol" > "$tmp/update-library.c"
    printf 'HOLY_1 { global: %s; local: *; };\n' "$symbol" > "$tmp/update-map"
    new library
    printf 'x-update-test %s\n' "$variant" >> "$tree/HOLY/meta"
    mkdir -p "$tree/DATA$runtime"
    gcc -shared -fPIC -Wl,-soname,libholyfixture.so.1 -Wl,--version-script="$tmp/update-map" \
        -o "$tree/DATA$library" "$tmp/update-library.c"
    patchelf --replace-needed libc.so.6 "$libc" "$tree/DATA$library"
    pack "update-$variant"
    if test "$variant" = compatible; then
        expect 0 "$bin" db plan-update "$provider" "$(hash update-compatible)" --root "$root"
        grep -q 'needed-path' "$tmp/out"
        grep -q "\"$probe\" .* \"$(hash update-compatible)\"" "$tmp/out"
        update_plan=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
        expect 0 "$bin" db apply-update "$update_plan" "$provider" "$(hash update-compatible)" --root "$root"
        expect 0 "$bin" db check --all --root "$root"
        if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
            doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/probe > "$tmp/update-run"
            grep -qx updated-probe "$tmp/update-run"
        fi
        expect 0 "$bin" db plan-update "$(hash update-compatible)" "$provider" --root "$root"
        update_plan=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
        expect 0 "$bin" db apply-update "$update_plan" "$(hash update-compatible)" "$provider" --root "$root"
    else
        expect 4 "$bin" db plan-update "$provider" "$(hash update-broken)" --root "$root"
        test ! -s "$tmp/out"
    fi
done
expect 0 "$bin" db check --all --root "$root"
expect 3 "$bin" db rm "$runtime_hash" --root "$root"
if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
    command -v doas >/dev/null && doas -n true || exit 6
    doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/probe > "$tmp/run"
    grep -qx dynamic-probe "$tmp/run"
    doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /lib64/ld-linux-x86-64.so.2 /usr/bin/probe > "$tmp/run"
    grep -qx dynamic-probe "$tmp/run"
    printf 'dynamic chroot probes passed\n'
fi
musl_loader=/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1
if test -n "${MUSL_CC:-}" || test -n "${MUSL_LIBC:-}" || test -n "${MUSL_PACKAGE:-}"; then
    test -x "${MUSL_CC:-}" || exit 6
    mkdir -p "$root/usr/lib/holy/x86_64-linux-musl" "$root/usr/share/licenses/musl" "$root/usr/share/doc/musl"
    ln -s usr/lib "$root/lib"
    if test -n "${MUSL_PACKAGE:-}"; then
        cp "$MUSL_PACKAGE" "$tmp/musl-runtime.holy"
        "$bin" cache stage "local:$tmp/musl-runtime.holy" --root "$root" > "$tmp/out"
    else
        test -f "${MUSL_LIBC:-}" || exit 6
        test "$(patchelf --print-soname "$MUSL_LIBC")" = libc.musl-x86_64.so.1 || {
            echo 'musl fixture requires a natively linked musl SONAME; do not rewrite the loader' >&2
            exit 6
        }
        new musl-runtime musl
        mkdir -p "$tree/DATA/usr/lib/holy/x86_64-linux-musl"
        cp -L "$MUSL_LIBC" "$tree/DATA$musl_loader"
        sha256sum "$MUSL_LIBC" > "$tree/HOLY/origin"
        ln -s holy/x86_64-linux-musl/ld-musl-x86_64.so.1 "$tree/DATA/usr/lib/ld-musl-x86_64.so.1"
        pack musl-runtime
    fi
    new probe musl
    mkdir -p "$tree/DATA/usr/bin"
    cat > "$tmp/musl.c" <<'C'
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
static void *worker(void *p) { return p; }
int main(void)
{
    pthread_t thread;
    void *value = malloc(64), *result;
    if (!value || pthread_create(&thread, NULL, worker, value) ||
        pthread_join(thread, &result) || result != value) return 1;
    free(value);
    return puts("musl-probe") < 0;
}
C
    "$MUSL_CC" -pthread -o "$tree/DATA/usr/bin/musl-probe" "$tmp/musl.c"
    patchelf --set-interpreter "$musl_loader" --replace-needed libc.so "$musl_loader" "$tree/DATA/usr/bin/musl-probe"
    pack musl-probe
    musl_runtime=$(hash musl-runtime) musl_probe=$(hash musl-probe)
    expect 0 "$bin" db plan-set "$musl_probe" "$musl_runtime" --root "$root"
    musl_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    expect 0 "$bin" db apply-set "$musl_plan" "$musl_probe" "$musl_runtime" --root "$root"
    if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
        doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/musl-probe > "$tmp/run"
        grep -qx musl-probe "$tmp/run"
        doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /lib/ld-musl-x86_64.so.1 /usr/bin/musl-probe > "$tmp/run"
        grep -qx musl-probe "$tmp/run"
    fi
fi
# keep the application installed while the owner removes its libc and loader.
if test "${HOLY_TEST_STATIC_RECOVERY:-0}" = 1; then
    "$bin" elf "$bin" > "$tmp/out"
    grep -qx 'runtime nolibc' "$tmp/out"
    command -v doas >/dev/null && doas -n true || exit 6
    cp "$bin" "$root/usr/bin/holypkg"
fi
rm "$root$libc" "$root$loader"
if test -n "${musl_runtime:-}"; then
    rm "$root$musl_loader"
    expect 4 "$bin" db check "$musl_probe" --root "$root" --json
    grep -q '"code":"broken-provider"' "$tmp/out"
fi
expect 4 "$bin" db check "$probe" --root "$root" --json
grep -q '"code":"broken-provider"' "$tmp/out"
test ! -e "$root$libc"
expect 0 repair_pkg db repair-plan "$runtime_hash"
repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
test "${#repair}" -eq 64
expect 3 repair_pkg db repair "$runtime_hash" --plan "$(printf '%064d' 0)"
test ! -e "$root$libc"
expect 0 repair_pkg db repair "$runtime_hash" --plan "$repair"
expect 0 "$bin" db check "$probe" --root "$root"
if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
    doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/probe > "$tmp/run"
    grep -qx dynamic-probe "$tmp/run"
    printf 'glibc cache recovery probe passed\n'
fi
if test -n "${musl_runtime:-}"; then
    expect 0 repair_pkg db repair-plan "$musl_runtime"
    repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
    expect 0 repair_pkg db repair "$musl_runtime" --plan "$repair"
    expect 0 "$bin" db check --all --root "$root"
    for removed in glibc musl; do
        if test "$removed" = glibc; then
            rm "$root$libc" "$root$loader" "$root/usr/lib64/ld-linux-x86-64.so.2"
            damaged=$runtime_hash
        else
            rm "$root$musl_loader" "$root/usr/lib/ld-musl-x86_64.so.1"
            damaged=$musl_runtime
        fi
        expect 0 repair_pkg db repair-plan "$damaged"
        repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
        expect 0 repair_pkg db repair "$damaged" --plan "$repair"
        expect 0 "$bin" db check --all --root "$root"
        test "$(readlink "$root/usr/lib64/ld-linux-x86-64.so.2")" = ../lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2
        test "$(readlink "$root/usr/lib/ld-musl-x86_64.so.1")" = holy/x86_64-linux-musl/ld-musl-x86_64.so.1
        if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
            doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/probe > "$tmp/run"
            grep -qx dynamic-probe "$tmp/run"
            doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/musl-probe > "$tmp/run"
            grep -qx musl-probe "$tmp/run"
        fi
        printf '%s individual recovery passed\n' "$removed"
    done
    printf 'dual-libc recovery fixture passed\n'
fi
# changed content is not silently overwritten by missing-only repair.
cp "$root$libc" "$tmp/saved-libc"
printf changed > "$root$libc"
expect 4 repair_pkg db repair-plan "$runtime_hash"
grep -qx changed "$root$libc"
cp "$tmp/saved-libc" "$root$libc"
expect 0 "$bin" db rm "$probe" --root "$root"
cp "$root/var/lib/holypkg/installed/$provider/state" "$tmp/provider-state"
cp "$root/var/lib/holypkg/installed/$runtime_hash/state" "$tmp/runtime-state"
expect 0 "$bin" db plan-set "$probe" --root "$root"
reuse_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
grep -q "^selected $provider .* installed$" "$tmp/out"
grep -q "^selected $runtime_hash .* installed$" "$tmp/out"
expect 0 "$bin" db apply-set "$reuse_plan" "$probe" --root "$root"
cmp "$tmp/provider-state" "$root/var/lib/holypkg/installed/$provider/state"
cmp "$tmp/runtime-state" "$root/var/lib/holypkg/installed/$runtime_hash/state"
expect 0 "$bin" db check --all --root "$root"
if test "${HOLY_TEST_DYNAMIC_CHROOT:-0}" = 1; then
    doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /usr/bin/probe > "$tmp/run"
    grep -qx dynamic-probe "$tmp/run"
fi
expect 0 "$bin" db rm "$probe" --root "$root"
expect 0 "$bin" db rm "$provider" --root "$root"
expect 0 "$bin" db rm "$runtime_hash" --root "$root"
test ! -e "$root$libc"
# a SONAME match in another directory does not satisfy a literal path.
new misplaced
mkdir -p "$tree/DATA/usr/lib"
cp "$tmp/library.so" "$tree/DATA/usr/lib/libholyfixture.so.1"
patchelf --replace-needed libc.so.6 "$libc" "$tree/DATA/usr/lib/libholyfixture.so.1"
pack misplaced
expect 4 "$bin" db plan-set "$probe" "$(hash misplaced)" "$runtime_hash" --root "$root"
# named search remains a decision until its launch context is modeled.
new named
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/probe" "$tree/DATA/usr/bin/named"
patchelf --set-interpreter "$loader" "$tree/DATA/usr/bin/named"
pack named
expect 3 "$bin" db plan-set "$(hash named)" "$provider" "$runtime_hash" --root "$root"
grep -q unknown-loader-search "$tmp/err"
if test "${HOLY_TEST_STATIC_RECOVERY:-0}" = 1; then
    printf 'static libc-free recovery fixture passed\n'
fi
printf 'dynamic placement fixtures passed\n'
