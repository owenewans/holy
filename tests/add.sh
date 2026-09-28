#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share"
"$bin" db init --root "$root" > "$tmp/out"

package() {
    name=$1
    dependency=$2
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' \
            "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$name" > "$tree/DATA/usr/share/$name"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    rm -r "$tree"
}

package app lib
package lib ''
app=$(sha256sum "$tmp/app.holy" | cut -d ' ' -f 1)
lib=$(sha256sum "$tmp/lib.holy" | cut -d ' ' -f 1)
if "$bin" add "local:$tmp/app.holy" --candidate "local:$tmp/lib.holy" \
    --root "$root" < /dev/null > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -q 'plan-set .* read-only' "$tmp/out"
grep -q 'decision-required plan=' "$tmp/err"
test ! -e "$root/usr/share/app"
test ! -e "$root/usr/share/lib"
test "$(cat "$root/var/lib/holypkg/generation")" -eq 0

if "$bin" add "local:$tmp/app.holy" --root "$root" --yes \
    > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" add "local:$tmp/app.holy" --candidate nope --root "$root" --yes \
    > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
"$bin" add "local:$tmp/app.holy" --candidate "local:$tmp/lib.holy" \
    --root "$root" --noninteractive --yes > "$tmp/out"
grep -q '^committed-set ' "$tmp/out"
grep -qx app "$root/usr/share/app"
grep -qx lib "$root/usr/share/lib"
grep -qx 'reason explicit' "$root/var/lib/holypkg/installed/$app/state"
grep -qx 'reason dependency' "$root/var/lib/holypkg/installed/$lib/state"
"$bin" db check --all --root "$root" > "$tmp/out"

interactive="$tmp/interactive"
mkdir -p "$interactive/usr/share"
"$bin" db init --root "$interactive" > "$tmp/out"
python3 - "$bin" "$tmp/lib.holy" "$interactive" <<'PY'
import os, pty, select, subprocess, sys, time

def answer(choice):
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.argv[1], 'add', 'local:' + sys.argv[2],
                             '--root', sys.argv[3]], stdin=slave, stdout=slave,
                            stderr=slave)
    os.close(slave)
    output = b''
    deadline = time.monotonic() + 15
    while b'? [y/N]' not in output:
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([master], [], [], remaining)[0], output
        output += os.read(master, 65536)
    os.write(master, choice + b'\n')
    status = proc.wait(timeout=15)
    os.close(master)
    return status

assert answer(b'n') == 3
assert not os.path.exists(sys.argv[3] + '/usr/share/lib')
assert answer(b'y') == 0
assert open(sys.argv[3] + '/usr/share/lib', encoding='utf-8').read() == 'lib\n'
PY

associated="$tmp/associated"
mkdir -p "$associated/usr/share"
"$bin" db init --root "$associated" > "$tmp/out"
printf '[source fixture]\ntype holy-http\nurl "https://example.invalid/"\n' > "$tmp/source.conf"
"$bin" source plan --config "$tmp/source.conf" --root "$associated" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$associated" > "$tmp/out"
"$bin" source list --root "$associated" > "$tmp/out"
source_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
test "${#source_id}" -eq 64
if "$bin" add "local:$tmp/lib.holy" --associate-source absent --root "$associated" --yes \
    > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -e "$associated/usr/share/lib"
"$bin" add "local:$tmp/lib.holy" --associate-source fixture --root "$associated" \
    --yes > "$tmp/out"
grep -q "binding $lib source $source_id" "$tmp/out"
grep -qx "source-id $source_id" "$associated/var/lib/holypkg/installed/$lib/state"
"$bin" db check "$lib" --root "$associated" > "$tmp/out"
printf '[source renamed]\ntype holy-http\nurl "https://example.invalid/"\n' > "$tmp/source.conf"
"$bin" source plan --config "$tmp/source.conf" --root "$associated" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$associated" > "$tmp/out"
if "$bin" add "local:$tmp/app.holy" --associate-source fixture --root "$associated" \
    --yes > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -e "$associated/usr/share/app"
"$bin" add "local:$tmp/app.holy" --associate-source renamed --root "$associated" \
    --yes > "$tmp/out"
grep -qx "source-id $source_id" "$associated/var/lib/holypkg/installed/$app/state"
"$bin" db check --all --root "$associated" > "$tmp/out"
both="$tmp/both-sources"
mkdir -p "$both/usr/share"
"$bin" db init --root "$both" > "$tmp/out"
"$bin" source plan --config "$tmp/source.conf" --root "$both" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$both" > "$tmp/out"
"$bin" source list --root "$both" > "$tmp/out"
both_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
if "$bin" add "local:$tmp/app.holy" --candidate "local:$tmp/lib.holy" \
    --associate "$app=renamed" --associate "$app=renamed" --root "$both" --yes \
    > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
if "$bin" add "local:$tmp/app.holy" --candidate "local:$tmp/lib.holy" \
    --associate "$(printf '%064d' 0)=renamed" --root "$both" --yes \
    > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
"$bin" add "local:$tmp/app.holy" --candidate "local:$tmp/lib.holy" \
    --associate-source renamed --associate "$lib=renamed" --root "$both" --yes > "$tmp/out"
grep -qx "source-id $both_id" "$both/var/lib/holypkg/installed/$app/state"
grep -qx "source-id $both_id" "$both/var/lib/holypkg/installed/$lib/state"
"$bin" db check --all --root "$both" > "$tmp/out"
printf 'local add fixtures passed\n'
