#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/repo" "$tmp/tree/HOLY" "$tmp/tree/DATA" \
    "$tmp/source-input" "$tmp/identity-root" "$tmp/image-root" \
    "$tmp/image/inputs" "$tmp/image/packages" "$tmp/image/work" "$tmp/fetched"
printf 'format holy-package-1\nname fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tmp/tree/HOLY/meta"
for member in files deps provides hooks origin transform; do
    : > "$tmp/tree/HOLY/$member"
done
printf 'require helper-1 fixture package helper any any any - helper metadata\n' > "$tmp/tree/HOLY/deps"
tar -cf "$tmp/fixture.tar" -C "$tmp/tree" HOLY DATA
lz4 -q "$tmp/fixture.tar" "$tmp/repo/fixture.holy"
sed 's/name fixture/name helper/' "$tmp/tree/HOLY/meta" > "$tmp/tree/HOLY/helper-meta"
mv "$tmp/tree/HOLY/helper-meta" "$tmp/tree/HOLY/meta"
: > "$tmp/tree/HOLY/deps"
tar -cf "$tmp/helper.tar" -C "$tmp/tree" HOLY DATA
lz4 -q "$tmp/helper.tar" "$tmp/repo/helper.holy"
"$bin" repo index "$tmp/repo" > "$tmp/result"
"$bin" repo seal "$tmp/repo" > "$tmp/result"
index=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
test "${#index}" -eq 64
printf '[source fixture]\ntype holy-http\nurl "https://fixture.example/holy/"\n' > "$tmp/source-input/sources.conf"
printf 'fixture\n' > "$tmp/source-input/aliases"
printf '%s\n' "$index" > "$tmp/source-input/fixture.index"
printf '%s\n' "$tmp/repo" > "$tmp/source-input/fixture.mirror"
printf 'yes\n' > "$tmp/source-input/fixture.embed"
mkdir "$tmp/limine" "$tmp/config-parts"
for input in kernel static-holypkg static-holyinstall static-cc busybox dinit mdevd; do
    : > "$tmp/$input"
done
cat > "$tmp/config-parts/image.conf" <<EOF
[image]
arch x86_64
output "../output"
kernel-image "../kernel"
kernel-version fixture
limine-dir "../limine"
static-holypkg "../static-holypkg"
static-holyinstall "../static-holyinstall"
static-cc "../static-cc"
profile static-core
root-storage ram
boot-test build-only
EOF
cat > "$tmp/image.conf" <<EOF
include "config-parts/image.conf"

[packages]
busybox "$tmp/busybox"
dinit "$tmp/dinit"
mdevd "$tmp/mdevd"
add fixture:fixture

[source fixture]
type holy-http
url "https://fixture.example/holy/"
index-sha256 "$index"
mirror "$tmp/repo"
embed-mirror yes

[docs]
include installed-man-pages
output "/usr/share/holy/llm.txt"
EOF
./holygetiso --check "$tmp/image.conf" > "$tmp/result"
grep -qx "source fixture index $index" "$tmp/result"
grep -qx 'add fixture:fixture' "$tmp/result"
grep -Fxq "output $tmp/config-parts/../output" "$tmp/result"
config_hash=$(sed -n 's/^config-sha256 //p' "$tmp/result")
sed 's/boot-test build-only/boot-test required/' "$tmp/config-parts/image.conf" \
    > "$tmp/config-parts/changed.conf"
mv "$tmp/config-parts/changed.conf" "$tmp/config-parts/image.conf"
./holygetiso --check "$tmp/image.conf" > "$tmp/result"
changed_hash=$(sed -n 's/^config-sha256 //p' "$tmp/result")
test "$config_hash" != "$changed_hash"
sed 's/boot-test required/boot-test build-only/' "$tmp/config-parts/image.conf" \
    > "$tmp/config-parts/restored.conf"
mv "$tmp/config-parts/restored.conf" "$tmp/config-parts/image.conf"
printf 'include "config-parts/cycle.conf"\n' > "$tmp/cycle.conf"
printf 'include "../cycle.conf"\n' > "$tmp/config-parts/cycle.conf"
if ./holygetiso --check "$tmp/cycle.conf" > "$tmp/result" 2> "$tmp/error"; then exit 1; fi
grep -q 'include cycle' "$tmp/error"
"$bin" db init --root "$tmp/identity-root" > "$tmp/result"
"$bin" source plan --config "$tmp/source-input/sources.conf" --root "$tmp/identity-root" > "$tmp/identity.plan"
identity_plan=$(sha256sum "$tmp/identity.plan")
identity_plan=${identity_plan%% *}
"$bin" source apply "$tmp/identity.plan" --sha256 "$identity_plan" --root "$tmp/identity-root" > "$tmp/result"
"$bin" source list --root "$tmp/identity-root" > "$tmp/result"
source_id=$(awk '$1 == "source" && $3 == "\"fixture\"" && $4 == "active" {print $2}' "$tmp/result")
test "${#source_id}" -eq 64
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$index" "$source_id" > "$tmp/repo/mirror-origin"
"$bin" db init --root "$tmp/image-root" > "$tmp/result"
: > "$tmp/image/build.record"
sh tools/image-source-stage.sh "$bin" "$tmp/image-root" "$tmp/image" "$tmp/source-input"
grep -qx "source fixture $source_id index $index" "$tmp/image/build.record"
sh tools/image-package-stage.sh "$bin" "$tmp/image" x86_64 \
    --source fixture fixture --source fixture fixture
test "$(wc -w < "$tmp/image/work/additional-packages")" -eq 2
test "$(wc -l < "$tmp/image/work/add-sources")" -eq 2
grep -q " $source_id$" "$tmp/image/work/add-sources"
"$bin" info "local:$tmp/image/inputs/add-0001.holy" > "$tmp/first-info"
"$bin" info "local:$tmp/image/inputs/add-0002.holy" > "$tmp/second-info"
sed -n 's/^name //p' "$tmp/first-info" "$tmp/second-info" | sort > "$tmp/names"
printf 'fixture\nhelper\n' > "$tmp/expected-names"
cmp "$tmp/names" "$tmp/expected-names"
printf '[install]\nroot "%s"\n' "$tmp/image-root" > "$tmp/image-install.conf"
for label in add-0001 add-0002; do
    artifact="$tmp/image/packages/$label.holy"
    digest=$(sha256sum "$artifact")
    digest=${digest%% *}
    "$bin" cache stage "local:$artifact" --root "$tmp/image-root" > "$tmp/result"
    printf 'artifact %s\nsource %s %s\n' "$digest" "$digest" "$source_id" \
        >> "$tmp/image-install.conf"
done
./holyinstall --config "$tmp/image-install.conf" --plan "$tmp/image-install.plan" \
    --holypkg "$bin" > "$tmp/result"
./holyinstall --apply "$tmp/image-install.plan" --holypkg "$bin" > "$tmp/result"
"$bin" db check --all --root "$tmp/image-root" > "$tmp/result"
printf 'fixture build plan\n' > "$tmp/image/plan"
printf 'fixture install plan\n' > "$tmp/image/install.plan"
python3 tools/image-host-tools.py "$tmp/image/host-tools.jsonl" sh python3
tools_hash=$(sha256sum "$tmp/image/host-tools.jsonl")
printf 'host-tools-sha256 %s\n' "${tools_hash%% *}" >> "$tmp/image/build.record"
plan_hash=$(sha256sum "$tmp/image/plan")
printf '%s\n' "${plan_hash%% *}" > "$tmp/image/boot-plan"
install_hash=$(sha256sum "$tmp/image/install.plan")
printf 'install-plan-file-sha256 %s\n' "${install_hash%% *}" >> "$tmp/image/build.record"
(
    cd "$tmp/image"
    find inputs packages mirrors -type f -print0 | sort -z | xargs -0 sha256sum > input-lock.sha256
)
lock=$(sha256sum "$tmp/image/input-lock.sha256")
printf 'input-lock-sha256 %s\n' "${lock%% *}" >> "$tmp/image/build.record"
./holygetiso --export-inputs "$tmp/image" "$tmp/export" > "$tmp/result"
test "$(cat "$tmp/result")" = "$tmp/export"
(cd "$tmp/export" && sha256sum -c SHA256SUMS > /dev/null)
cmp "$tmp/image/inputs/add-0001.holy" "$tmp/export/inputs/add-0001.holy"
cmp "$tmp/image/mirrors/fixture/current" "$tmp/export/mirrors/fixture/current"
if ./holygetiso --export-inputs "$tmp/image" "$tmp/export" > "$tmp/result" 2> "$tmp/error"; then exit 1; fi
printf 'changed\n' >> "$tmp/image/inputs/add-0001.holy"
if ./holygetiso --export-inputs "$tmp/image" "$tmp/changed-export" > "$tmp/result" 2> "$tmp/error"; then exit 1; fi
test ! -e "$tmp/changed-export"
cp "$tmp/export/inputs/add-0001.holy" "$tmp/image/inputs/add-0001.holy"
printf '{}\n' >> "$tmp/image/host-tools.jsonl"
if ./holygetiso --export-inputs "$tmp/image" "$tmp/changed-tools" > "$tmp/result" 2> "$tmp/error"; then exit 1; fi
test ! -e "$tmp/changed-tools"
"$bin" fetch fixture:fixture --catalog "$tmp/image/mirrors/fixture" \
    --root "$tmp/image-root" --output "$tmp/fetched" > "$tmp/result"
test -f "$tmp/fetched/$(sha256sum "$tmp/repo/fixture.holy" | cut -d ' ' -f 1).holy"
"$bin" source list --root "$tmp/image-root" > "$tmp/result"
grep -qx "source $source_id \"fixture\" active" "$tmp/result"
grep -q '^root-path "/var/cache/holypkg/image-mirrors/fixture"$' \
    "$tmp/image-root/var/lib/holypkg/catalogs/$source_id"
mv "$tmp/image-root" "$tmp/relocated-root"
mkdir "$tmp/relocated-fetch"
"$bin" db check --all --root "$tmp/relocated-root" > "$tmp/result"
"$bin" fetch fixture:fixture --root "$tmp/relocated-root" \
    --output "$tmp/relocated-fetch" > "$tmp/result"
test -f "$tmp/relocated-fetch/$(sha256sum "$tmp/repo/fixture.holy" | cut -d ' ' -f 1).holy"
mkdir "$tmp/wrong-root" "$tmp/wrong-image"
mkdir "$tmp/wrong-image/inputs" "$tmp/wrong-image/work"
: > "$tmp/wrong-image/build.record"
"$bin" db init --root "$tmp/wrong-root" > "$tmp/result"
printf '%064d\n' 0 > "$tmp/source-input/fixture.index"
if sh tools/image-source-stage.sh "$bin" "$tmp/wrong-root" "$tmp/wrong-image" \
    "$tmp/source-input" > "$tmp/result" 2> "$tmp/error"; then exit 1; fi
test ! -e "$tmp/wrong-image/mirrors/fixture/current"
printf '%s\n' "$index" > "$tmp/source-input/fixture.index"
rm "$tmp/source-input/fixture.embed"
mkdir "$tmp/minimal-root" "$tmp/minimal-image"
mkdir "$tmp/minimal-image/inputs" "$tmp/minimal-image/packages" "$tmp/minimal-image/work"
: > "$tmp/minimal-image/build.record"
"$bin" db init --root "$tmp/minimal-root" > "$tmp/result"
sh tools/image-source-stage.sh "$bin" "$tmp/minimal-root" "$tmp/minimal-image" "$tmp/source-input"
test ! -e "$tmp/minimal-root/var/cache/holypkg/image-mirrors"
sh tools/image-package-stage.sh "$bin" "$tmp/minimal-image" x86_64 \
    --source fixture fixture
test "$(wc -w < "$tmp/minimal-image/work/additional-packages")" -eq 2
openssl genpkey -algorithm ED25519 -out "$tmp/signer.pem" > "$tmp/result" 2> "$tmp/error"
openssl pkey -in "$tmp/signer.pem" -pubout -out "$tmp/public.pem" > "$tmp/result" 2> "$tmp/error"
"$bin" repo seal "$tmp/repo" --key "$tmp/signer.pem" > "$tmp/result"
openssl pkey -pubin -in "$tmp/public.pem" -outform DER -out "$tmp/public.der"
raw=$(python3 - "$tmp/public.der" <<'PY'
import pathlib, sys
print(pathlib.Path(sys.argv[1]).read_bytes()[-32:].hex())
PY
)
test "${#raw}" -eq 64
key_hash=$(python3 - "$raw" <<'PY'
import hashlib, sys
print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())
PY
)
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification ed25519-pinned-key\npublic-key-sha256 %s\nsource-id %s\n' \
    "$index" "$key_hash" "$source_id" > "$tmp/repo/mirror-origin"
python3 - "$tmp/image.conf" "$tmp/signed-image.conf" "$tmp/public.pem" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
text = text.replace('embed-mirror yes\n', 'embed-mirror yes\ntrust require\npublic-key "' + sys.argv[3] + '"\n')
pathlib.Path(sys.argv[2]).write_text(text)
PY
./holygetiso --check "$tmp/signed-image.conf" > "$tmp/result"
signed_hash=$(sed -n 's/^config-sha256 //p' "$tmp/result")
test "${#signed_hash}" -eq 64
test "$signed_hash" != "$config_hash"
cp "$tmp/public.pem" "$tmp/public-original.pem"
openssl genpkey -algorithm ED25519 -out "$tmp/other-signer.pem" > "$tmp/result" 2> "$tmp/error"
openssl pkey -in "$tmp/other-signer.pem" -pubout -out "$tmp/public.pem" > "$tmp/result" 2> "$tmp/error"
./holygetiso --check "$tmp/signed-image.conf" > "$tmp/result"
other_hash=$(sed -n 's/^config-sha256 //p' "$tmp/result")
test "$other_hash" != "$signed_hash"
cp "$tmp/public-original.pem" "$tmp/public.pem"
mkdir -p "$tmp/signed-input" "$tmp/signed-root" "$tmp/signed-image/inputs" "$tmp/signed-image/work"
printf '[source fixture]\ntype holy-http\nurl "https://fixture.example/holy/"\ntrust require\npublic-key-ed25519 %s\n' \
    "$raw" > "$tmp/signed-input/sources.conf"
printf 'fixture\n' > "$tmp/signed-input/aliases"
printf '%s\n' "$index" > "$tmp/signed-input/fixture.index"
printf '%s\n' "$tmp/repo" > "$tmp/signed-input/fixture.mirror"
printf 'yes\n' > "$tmp/signed-input/fixture.embed"
: > "$tmp/signed-image/build.record"
"$bin" db init --root "$tmp/signed-root" > "$tmp/result"
sh tools/image-source-stage.sh "$bin" "$tmp/signed-root" "$tmp/signed-image" "$tmp/signed-input"
"$bin" search fixture --source fixture --root "$tmp/signed-root" > "$tmp/result"
grep -qx 'listed 1 packages' "$tmp/result"
printf '\001' | dd of="$tmp/signed-root/var/cache/holypkg/image-mirrors/fixture/signature.$index" bs=1 seek=0 conv=notrunc status=none
if "$bin" search fixture --source fixture --root "$tmp/signed-root" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 6; fi
printf 'image source staging passed\n'
