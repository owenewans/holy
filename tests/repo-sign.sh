#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/repo" "$tmp/unsigned" "$tmp/tree/HOLY" "$tmp/tree/DATA/usr/share"
printf 'format holy-package-1\nname signed-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tmp/tree/HOLY/meta"
for member in deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$member"; done
printf 'signed\n' > "$tmp/tree/DATA/usr/share/signed-fixture"
"$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
mv "$tmp/files" "$tmp/tree/HOLY/files"
"$bin" pack "$tmp/tree" --output "$tmp/repo/fixture.holy" > "$tmp/out"
cp "$tmp/repo/fixture.holy" "$tmp/unsigned/fixture.holy"
openssl genpkey -algorithm ED25519 -out "$tmp/key.pem" > /dev/null 2> "$tmp/err"
openssl pkey -in "$tmp/key.pem" -pubout -out "$tmp/pub.pem" > /dev/null 2> "$tmp/err"
openssl genpkey -algorithm ED25519 -out "$tmp/wrong.pem" > /dev/null 2> "$tmp/err"
openssl pkey -in "$tmp/wrong.pem" -pubout -out "$tmp/wrong-pub.pem" > /dev/null 2> "$tmp/err"
"$bin" repo index "$tmp/repo" > "$tmp/out"
"$bin" repo seal "$tmp/repo" --key "$tmp/key.pem" > "$tmp/out"
hash=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
test "${#hash}" -eq 64
test "$(wc -c < "$tmp/repo/signature.$hash")" -eq 64
"$bin" repo verify "$tmp/repo" --key "$tmp/pub.pem" > "$tmp/out"
grep -qx "verified $hash" "$tmp/out"
root="$tmp/source-root"
mkdir "$root"
"$bin" db init --root "$root" > "$tmp/out"
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\ntrust require\npublic-key "%s"\n' \
    "$tmp/pub.pem" > "$tmp/source.conf"
"$bin" source plan --config "$tmp/source.conf" --root "$root" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root" > "$tmp/out"
"$bin" source list --root "$root" > "$tmp/out"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/out")
test "${#source_id}" -eq 64
key_raw=$(awk -v id="$source_id" '$1 == "source" && $2 == id {print $NF}' "$root/var/lib/holypkg/sources")
key_hash=$(python3 - "$key_raw" <<'PY'
import hashlib, sys
print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())
PY
)
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification ed25519-pinned-key\npublic-key-sha256 %s\nsource-id %s\n' \
    "$hash" "$key_hash" "$source_id" > "$tmp/repo/mirror-origin"
"$bin" source catalog bind fixture "$tmp/repo" --root "$root" > "$tmp/out"
"$bin" search signed-fixture --source fixture --root "$root" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
cp "$tmp/repo/signature.$hash" "$tmp/signed-source-signature"
printf '\001' | dd of="$tmp/repo/signature.$hash" bs=1 seek=0 conv=notrunc status=none
if "$bin" search signed-fixture --source fixture --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
cp "$tmp/signed-source-signature" "$tmp/repo/signature.$hash"
sed "s|$tmp/pub.pem|$tmp/wrong-pub.pem|" "$tmp/source.conf" > "$tmp/rotated.conf"
"$bin" source plan --config "$tmp/rotated.conf" --root "$root" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root" > "$tmp/out"
"$bin" source list --root "$root" > "$tmp/out"
grep -qx "source $source_id \"fixture\" active" "$tmp/out"
if "$bin" search signed-fixture --source fixture --root "$root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
"$bin" repo seal "$tmp/repo" --key "$tmp/key.pem" > "$tmp/out"
if "$bin" repo verify "$tmp/repo" --key "$tmp/wrong-pub.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" repo seal "$tmp/repo" --key "$tmp/wrong.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cp "$tmp/repo/signature.$hash" "$tmp/signature"
printf '\001' | dd of="$tmp/repo/signature.$hash" bs=1 seek=0 conv=notrunc status=none
if "$bin" repo verify "$tmp/repo" --key "$tmp/pub.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
cp "$tmp/signature" "$tmp/repo/signature.$hash"
cp "$tmp/repo/fixture.holy" "$tmp/artifact"
printf 'tampered\n' >> "$tmp/repo/fixture.holy"
if "$bin" repo verify "$tmp/repo" --key "$tmp/pub.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
cp "$tmp/artifact" "$tmp/repo/fixture.holy"
printf 'tampered\n' >> "$tmp/repo/index.$hash"
if "$bin" repo verify "$tmp/repo" --key "$tmp/pub.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
"$bin" repo index "$tmp/unsigned" > "$tmp/out"
"$bin" repo seal "$tmp/unsigned" > "$tmp/out"
if "$bin" repo verify "$tmp/unsigned" --key "$tmp/pub.pem" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
