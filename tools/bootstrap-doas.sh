#!/bin/sh
set -eu
test "$#" -eq 4 || {
    echo 'usage: bootstrap-doas.sh HOLYPKG OPENDOAS-GIT STATIC-PREFIX OUTPUT' >&2
    exit 2
}
if test "${HOLY_DOAS_NAMESPACE:-}" != 1; then
    test "$(id -u)" != 0 || exit 6
    export HOLY_DOAS_NAMESPACE=1
    exec unshare --map-root-user -- sh "$0" "$@"
fi
test "$(id -u)" = 0 || exit 6
umask 022
bin=$(realpath "$1")
source=$(realpath "$2")
prefix=$(realpath "$3")
test -x "$bin" && test -x "$prefix/bin/holy-musl-gcc" || exit 6
test "$(git -C "$source" rev-parse HEAD)" = 7f0205fe2f06221d76243342d299851f48c2b83c || exit 6
for tool in git tar make yacc sha256sum; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
mkdir -p "$(dirname "$4")"
mkdir "$4"
out=$(realpath "$4")
work="$out/work"
mkdir "$work"
started=$(date +%s)
finish() {
    rc=$?
    trap - EXIT
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$out/build.record"
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
printf 'format holy-doas-bootstrap-1\narch x86_64\nsource-commit %s\n' \
    7f0205fe2f06221d76243342d299851f48c2b83c > "$out/build.record"
git -C "$source" archive HEAD | tar -xf - -C "$work"
(
    cd "$work"
    CC="$prefix/bin/holy-musl-gcc" ./configure --prefix=/usr --enable-static \
        --with-shadow --without-pam
    make CC="$prefix/bin/holy-musl-gcc"
)
"$bin" elf "$work/doas" > "$out/doas.elf"
grep -qx 'runtime nolibc' "$out/doas.elf"
grep -qx 'e_type 2' "$out/doas.elf"
grep -qx 'machine x86_64' "$out/doas.elf"
tree="$work/package"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin" \
    "$tree/DATA/usr/share/man/man1" "$tree/DATA/usr/share/man/man5" \
    "$tree/DATA/usr/share/licenses/doas"
cp "$work/doas" "$tree/DATA/usr/bin/doas"
chmod 4755 "$tree/DATA/usr/bin/doas"
cp "$work/doas.1" "$tree/DATA/usr/share/man/man1/"
cp "$work/doas.conf.5" "$tree/DATA/usr/share/man/man5/"
cp "$work/LICENSE" "$tree/DATA/usr/share/licenses/doas/"
cat > "$tree/HOLY/meta" <<'EOF'
format holy-package-1
name doas
version 6.8.2
release 1
os linux
arch x86_64
libc nolibc
summary "static OpenDoas with shadow authentication"
EOF
for field in deps provides hooks transform; do : > "$tree/HOLY/$field"; done
cp "$out/build.record" "$tree/HOLY/origin"
printf 'configure --enable-static --with-shadow --without-pam\n' >> "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$work/files"
cp "$work/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/doas.holy"
"$bin" info "local:$out/doas.holy" > "$out/package.record"
sha256sum "$out/doas.holy" "$tree/DATA/usr/bin/doas" >> "$out/build.record"
