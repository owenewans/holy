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
"$bin" source show fixture --root "$root" > "$tmp/out"
key_hash=$(sed -n 's/^public-key-sha256 //p' "$tmp/out")
test "${#key_hash}" -eq 64
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
# a source that registered a key proves the generation a plan fixes: the plan names the
# signature, and the apply proves it again against the same catalog
openssl genpkey -algorithm ED25519 -out "$tmp/update-key.pem" > /dev/null 2> "$tmp/err"
openssl pkey -in "$tmp/update-key.pem" -pubout -out "$tmp/update-pub.pem" > /dev/null 2> "$tmp/err"
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\ntrust require\npublic-key "%s"\n' \
    "$tmp/update-pub.pem" > "$tmp/update-source.conf"
cp -a "$tmp/repo" "$tmp/update-repo"
rm -rf "$tmp/update-repo/index" "$tmp/update-repo"/index.* "$tmp/update-repo"/signature.* \
    "$tmp/update-repo/current" "$tmp/update-repo"/*.holy "$tmp/update-repo/mirror-origin"
mkdir -p "$tmp/update-tree/HOLY" "$tmp/update-tree/DATA/usr/share"
printf 'format holy-package-1\nname signed-update\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tmp/update-tree/HOLY/meta"
printf 'x-version-family holy\n' >> "$tmp/update-tree/HOLY/meta"
for member in deps provides hooks origin transform; do : > "$tmp/update-tree/HOLY/$member"; done
printf 'signed one\n' > "$tmp/update-tree/DATA/usr/share/signed-update"
"$bin" manifest generate "$tmp/update-tree" --output "$tmp/update-files" > "$tmp/out"
mv "$tmp/update-files" "$tmp/update-tree/HOLY/files"
"$bin" pack "$tmp/update-tree" --output "$tmp/update-repo/signed-update.holy" > "$tmp/out"
"$bin" repo index "$tmp/update-repo" > "$tmp/out"
"$bin" repo seal "$tmp/update-repo" --key "$tmp/update-key.pem" > "$tmp/out"
update_index=$(sed -n 's/^sha256 //p' "$tmp/update-repo/current")
test "${#update_index}" -eq 64
mkdir "$tmp/update-root"
"$bin" db init --root "$tmp/update-root" > "$tmp/out"
"$bin" source plan --config "$tmp/update-source.conf" --root "$tmp/update-root" > "$tmp/source.plan"
update_source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$update_source_plan" \
    --root "$tmp/update-root" > "$tmp/out"
"$bin" source show fixture --root "$tmp/update-root" > "$tmp/out"
update_key_hash=$(sed -n 's/^public-key-sha256 //p' "$tmp/out")
test "${#update_key_hash}" -eq 64
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification ed25519-pinned-key\npublic-key-sha256 %s\nsource-id %s\n' \
    "$update_index" "$update_key_hash" "$source_id" > "$tmp/update-repo/mirror-origin"
"$bin" source catalog bind fixture "$tmp/update-repo" --root "$tmp/update-root" > "$tmp/out"
"$bin" add fixture:signed-update --root "$tmp/update-root" --yes > "$tmp/out"
grep -qx 'signed one' "$tmp/update-root/usr/share/signed-update"
cp -a "$tmp/update-tree" "$tmp/update-tree-2"
sed -i 's/^version 1$/version 2/' "$tmp/update-tree-2/HOLY/meta"
printf 'signed two\n' > "$tmp/update-tree-2/DATA/usr/share/signed-update"
"$bin" manifest generate "$tmp/update-tree-2" --output "$tmp/update-files-2" > "$tmp/out"
mv "$tmp/update-files-2" "$tmp/update-tree-2/HOLY/files"
"$bin" pack "$tmp/update-tree-2" --output "$tmp/signed-update-2.holy" > "$tmp/out"
rm "$tmp/update-repo/signed-update.holy"
mv "$tmp/signed-update-2.holy" "$tmp/update-repo/signed-update.holy"
"$bin" repo index "$tmp/update-repo" > "$tmp/out"
"$bin" repo seal "$tmp/update-repo" --key "$tmp/update-key.pem" > "$tmp/out"
new_index=$(sed -n 's/^sha256 //p' "$tmp/update-repo/current")
test "$new_index" != "$update_index"
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification ed25519-pinned-key\npublic-key-sha256 %s\nsource-id %s\n' \
    "$new_index" "$update_key_hash" "$source_id" > "$tmp/update-repo/mirror-origin"
"$bin" source catalog bind fixture "$tmp/update-repo" --root "$tmp/update-root" > "$tmp/out"
up_plan() {
    rm -f "$tmp/signed.plan"
    if "$bin" up fixture:signed-update --prepare --output "$tmp/signed.plan" \
        --root "$tmp/update-root" > "$tmp/out" 2> "$tmp/err"; then test "$1" -eq 0; else test "$?" -eq "$1"; fi
}
up_plan 0
grep -qx 'signature signed' "$tmp/signed.plan"
signed_plan=$(sha256sum "$tmp/signed.plan" | cut -d ' ' -f 1)
# the signature that verified while the plan was prepared must verify at the apply
cp "$tmp/update-repo/signature.$new_index" "$tmp/signed-signature"
printf '\001' | dd of="$tmp/update-repo/signature.$new_index" bs=1 seek=0 conv=notrunc status=none
up_plan 6
grep -q 'bound catalog unavailable' "$tmp/err"
if "$bin" apply "$tmp/signed.plan" --sha256 "$signed_plan" --root "$tmp/update-root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
cp "$tmp/signed-signature" "$tmp/update-repo/signature.$new_index"
up_plan 0
"$bin" apply "$tmp/signed.plan" --sha256 "$signed_plan" --root "$tmp/update-root" > "$tmp/out" 2> "$tmp/err"
grep -qx 'signed two' "$tmp/update-root/usr/share/signed-update"
"$bin" db check --all --root "$tmp/update-root" > "$tmp/out"
# a plan that claims a state the catalog cannot prove is refused
sed 's/^signature signed$/signature unsigned/' "$tmp/signed.plan" > "$tmp/forged.plan"
forged_plan=$(sha256sum "$tmp/forged.plan" | cut -d ' ' -f 1)
if "$bin" apply "$tmp/forged.plan" --sha256 "$forged_plan" --root "$tmp/update-root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
