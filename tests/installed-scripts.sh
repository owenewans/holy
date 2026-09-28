#!/bin/sh
set -eu
bin=$(realpath "$1")
compiler=${HOLY_FIXTURE_CC:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/bin"
"$bin" db init --root "$root" > "$tmp/out"
cat > "$tmp/interpreter.S" <<'ASM'
#if defined(__x86_64__)
.global _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
#elif defined(__i386__)
.global _start
_start:
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
#else
#error unsupported fixture architecture
#endif
ASM
"$compiler" -nostdlib -static -o "$tmp/interpreter" "$tmp/interpreter.S"
case $(uname -m) in
    x86_64) arch=x86_64 ;;
    i?86) arch=x86 ;;
    *) exit 6 ;;
esac

package() {
    name=$1
    line=$2
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch %s\nlibc nolibc\n' "$name" \
        "$(test "$line" = ELF && printf %s "$arch" || printf noarch)" > "$tree/HOLY/meta"
    for part in deps provides hooks origin transform; do : > "$tree/HOLY/$part"; done
    if test "$line" = ELF; then cp "$tmp/interpreter" "$tree/DATA/usr/bin/$name"
    else printf '%s\nexit 0\n' "$line" > "$tree/DATA/usr/bin/$name"; fi
    chmod 755 "$tree/DATA/usr/bin/$name"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "${package_root:-$root}" > "$tmp/out"
    rm -r "$tree"
}

package direct '#!/usr/bin/sh-fixture'
package sh-fixture ELF
package via-env '#!/usr/bin/env sh-fixture'
direct=$(sha256sum "$tmp/direct.holy" | cut -d ' ' -f 1)
provider=$(sha256sum "$tmp/sh-fixture.holy" | cut -d ' ' -f 1)
via_env=$(sha256sum "$tmp/via-env.holy" | cut -d ' ' -f 1)
if "$bin" db plan-set "$direct" --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" db plan-set "$via_env" "$provider" --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
"$bin" db plan-set "$direct" "$provider" --root "$root" > "$tmp/out"
grep -q 'shebang' "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db apply-set "$plan" "$direct" "$provider" --root "$root" > "$tmp/out"

"$bin" db check "$direct" --root "$root" --json > "$tmp/out"
grep -q '"state":"pass"' "$tmp/out"
python3 - "$bin" "$direct" "$root" > "$tmp/out" 2> "$tmp/err" <<'PY'
import ctypes, errno, os, sys
class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filters', ctypes.POINTER(Filter))]
rules = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, 437),
                    Filter(0x06, 0, 0, 0x50000 | errno.ENOSYS),
                    Filter(0x06, 0, 0, 0x7fff0000))
program = Program(4, rules)
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(38, 1, 0, 0, 0) == 0
assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0
for selected in (sys.argv[2], '--all'):
    pid = os.fork()
    if pid == 0:
        os.execv(sys.argv[1], [sys.argv[1], 'db', 'check', selected,
                                '--root', sys.argv[3], '--json'])
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 6
PY
grep -q '"code":"unavailable-path-resolution"' "$tmp/out"
test "$(grep -c '"unknown":1' "$tmp/out")" -eq 2
test -f "$root/usr/bin/direct"
cp -p "$root/usr/bin/sh-fixture" "$tmp/interpreter-good"
printf 'invalid ELF\n' > "$root/usr/bin/sh-fixture"
if "$bin" db check "$direct" --root "$root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -q '"code":"unknown-interpreter".*"target":"/usr/bin/sh-fixture"' "$tmp/out"
grep -q '"code":"broken-provider"' "$tmp/out"
cp -p "$tmp/interpreter-good" "$root/usr/bin/sh-fixture"
if "$bin" db rm "$provider" --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
"$bin" db rm "$provider" --accept-broken --root "$root" > "$tmp/out" 2> "$tmp/err"
if "$bin" db check "$direct" --root "$root" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -q '"code":"missing-interpreter".*"path":"usr/bin/direct".*"target":"/usr/bin/sh-fixture"' "$tmp/out"
grep -q '"code":"broken-provider"' "$tmp/out"

root2="$tmp/root2"
mkdir -p "$root2/usr/bin"
"$bin" db init --root "$root2" > "$tmp/out"
package_root=$root2
package shell-script '#!/bin/sh'
package busybox ELF
unset package_root
alias_package() {
    name=$1
    path=$2
    target=$3
    mkdir -p "$tree/HOLY" "$tree/DATA/$(dirname "$path")"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for part in deps provides hooks origin transform; do : > "$tree/HOLY/$part"; done
    ln -s "$target" "$tree/DATA/$path"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root2" > "$tmp/out"
    rm -r "$tree"
}
alias_package merged-bin bin usr/bin
alias_package shell-link usr/bin/sh busybox
alias_package shell-cycle usr/bin/sh ../../bin/sh
script=$(sha256sum "$tmp/shell-script.holy" | cut -d ' ' -f 1)
busybox=$(sha256sum "$tmp/busybox.holy" | cut -d ' ' -f 1)
merged=$(sha256sum "$tmp/merged-bin.holy" | cut -d ' ' -f 1)
shell_link=$(sha256sum "$tmp/shell-link.holy" | cut -d ' ' -f 1)
cycle=$(sha256sum "$tmp/shell-cycle.holy" | cut -d ' ' -f 1)
if "$bin" db plan-set "$script" "$busybox" "$shell_link" --root "$root2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" db plan-set "$script" "$busybox" "$cycle" "$merged" --root "$root2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
"$bin" db plan-set "$script" "$busybox" "$shell_link" "$merged" --root "$root2" > "$tmp/out"
grep -q 'path-alias /bin' "$tmp/out"
grep -q 'path-alias /usr/bin/sh' "$tmp/out"
grep -q 'shebang /usr/bin/busybox' "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db apply-set "$plan" "$script" "$busybox" "$shell_link" "$merged" --root "$root2" > "$tmp/out"
"$bin" db check "$script" --root "$root2" --json > "$tmp/out"
grep -q '"state":"pass"' "$tmp/out"
if "$bin" db rm "$merged" --root "$root2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
if "$bin" db rm "$shell_link" --root "$root2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
if "$bin" db rm "$busybox" --root "$root2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi

root3="$tmp/root3"
mkdir -p "$root3/usr/bin"
"$bin" db init --root "$root3" > "$tmp/out"
for name in busybox shell-link merged-bin shell-script; do
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root3" > "$tmp/out"
done
for artifact in "$busybox" "$shell_link" "$merged"; do
    "$bin" db plan-set "$artifact" --root "$root3" > "$tmp/out"
    plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    "$bin" db apply-set "$plan" "$artifact" --root "$root3" > "$tmp/out"
done
"$bin" db plan-set "$script" --root "$root3" > "$tmp/out"
grep -q "provider $merged path-alias /bin" "$tmp/out"
grep -q "provider $shell_link path-alias /usr/bin/sh" "$tmp/out"
grep -q "provider $busybox shebang /usr/bin/busybox" "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db apply-set "$plan" "$script" --root "$root3" > "$tmp/out"
"$bin" db check "$script" --root "$root3" --json > "$tmp/out"
grep -q '"state":"pass"' "$tmp/out"
"$bin" db rm "$shell_link" --accept-broken --root "$root3" > "$tmp/out" 2> "$tmp/err"
if "$bin" db check "$script" --root "$root3" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -q '"code":"broken-provider"' "$tmp/out"
grep -q '"code":"missing-interpreter"' "$tmp/out"

printf 'installed script checks passed\n'
