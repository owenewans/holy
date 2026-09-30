#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/repo" "$tmp/tree/HOLY" "$tmp/tree/DATA/usr/share" "$tmp/root"
printf 'format holy-package-1\nname git-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tmp/tree/HOLY/meta"
for member in deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$member"; done
printf 'git fixture\n' > "$tmp/tree/DATA/usr/share/git-fixture"
"$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
mv "$tmp/files" "$tmp/tree/HOLY/files"
"$bin" pack "$tmp/tree" --output "$tmp/repo/fixture.holy" > "$tmp/out"
"$bin" repo index "$tmp/repo" > "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
index=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
git -C "$tmp/repo" init -q
git -C "$tmp/repo" -c user.name=fixture -c user.email=fixture@example.invalid add .
git -C "$tmp/repo" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm fixture
commit=$(git -C "$tmp/repo" rev-parse HEAD)
printf '[source fixture]\ntype holy-git\nurl "file://%s/repo"\ntrust warn\n' "$tmp" > "$tmp/config"
"$bin" db init --root "$tmp/root" > "$tmp/out"
"$bin" source plan --config "$tmp/config" --root "$tmp/root" > "$tmp/plan"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/plan" --sha256 "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" sync fixture --root "$tmp/root" --sha256 "$index" --commit "$commit" > "$tmp/out" 2> "$tmp/err"
"$bin" search git-fixture --source fixture --root "$tmp/root" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
openssl genpkey -algorithm ED25519 -out "$tmp/private.pem" > /dev/null 2> "$tmp/err"
openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem" > /dev/null 2> "$tmp/err"
"$bin" repo seal "$tmp/repo" --key "$tmp/private.pem" > "$tmp/out"
git -C "$tmp/repo" add .
git -C "$tmp/repo" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm signed
signed_commit=$(git -C "$tmp/repo" rev-parse HEAD)
mkdir "$tmp/signed-root"
"$bin" db init --root "$tmp/signed-root" > "$tmp/out"
printf '[source fixture]\ntype holy-git\nurl "file://%s/repo"\ntrust require\npublic-key "%s/public.pem"\n' "$tmp" "$tmp" > "$tmp/signed-config"
"$bin" source plan --config "$tmp/signed-config" --root "$tmp/signed-root" > "$tmp/signed-plan" 2> "$tmp/signed-plan.err"
plan=$(sha256sum "$tmp/signed-plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/signed-plan" --sha256 "$plan" --root "$tmp/signed-root" > "$tmp/out"
signed_source=$(sed -n 's/^add-source \([0-9a-f]*\) "fixture"$/\1/p' "$tmp/signed-plan.err")
test "${#signed_source}" -eq 64
"$bin" sync fixture --root "$tmp/signed-root" --sha256 "$index" --commit "$signed_commit" > "$tmp/out" 2> "$tmp/err"
"$bin" search git-fixture --source fixture --root "$tmp/signed-root" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
if "$bin" sync fixture --root "$tmp/signed-root" --sha256 "$index" --commit "$commit" --output "$tmp/unsigned-output" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
# the same key enrolled under a name backs a source without repeating its path, and
# the frozen source record is the one the path produced
enrolled_root="$tmp/enrolled-root"
mkdir "$enrolled_root"
"$bin" db init --root "$enrolled_root" > "$tmp/out"
"$bin" key add fixture-key "$tmp/public.pem" --root "$enrolled_root" > "$tmp/out"
grep -q 'enrolled$' "$tmp/out"
"$bin" key list --root "$enrolled_root" > "$tmp/out"
grep -qx 'generation 0 keys 1 read-only' "$tmp/out"
"$bin" key show fixture-key --root "$enrolled_root" > "$tmp/out"
grep -q ' intact$' "$tmp/out"
printf '[source fixture]\ntype holy-git\nurl "file://%s/repo"\ntrust require\npublic-key "fixture-key"\n' "$tmp" > "$tmp/enrolled-config"
"$bin" source plan --config "$tmp/enrolled-config" --root "$enrolled_root" > "$tmp/enrolled-plan" 2> "$tmp/enrolled-plan.err"
grep -qx "add-source $signed_source \"fixture\"" "$tmp/enrolled-plan.err"
enrolled_plan=$(sha256sum "$tmp/enrolled-plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/enrolled-plan" --sha256 "$enrolled_plan" --root "$enrolled_root" > "$tmp/out"
"$bin" sync fixture --root "$enrolled_root" --sha256 "$index" --commit "$signed_commit" \
    --output "$tmp/enrolled-mirror" > "$tmp/out" 2> "$tmp/err"
grep -qx "verification ed25519-pinned-key" "$tmp/enrolled-mirror/mirror-origin"
# a name nothing enrolled, a name that traverses and a file that is not a key
printf '[source fixture]\ntype holy-git\nurl "file://%s/repo"\ntrust require\npublic-key "absent-key"\n' "$tmp" > "$tmp/absent-config"
if "$bin" source plan --config "$tmp/absent-config" --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -q 'no enrolled key: absent-key' "$tmp/err"
printf 'not a key\n' > "$tmp/not-a-key"
if "$bin" key add not-a-key "$tmp/not-a-key" --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
if "$bin" key add ../escape "$tmp/public.pem" --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
# a key changed after enrollment is refused by name, and the enrollment is readable
printf 'tampered\n' > "$enrolled_root/var/lib/holypkg/keys/fixture-key"
if "$bin" source plan --config "$tmp/enrolled-config" --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -q 'enrolled key changed: fixture-key' "$tmp/err"
if "$bin" key show fixture-key --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
"$bin" key list --root "$enrolled_root" > "$tmp/out"
grep -q ' changed$' "$tmp/out"
if "$bin" key remove fixture-key --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
"$bin" key remove fixture-key --root "$enrolled_root" --yes > "$tmp/out"
if "$bin" key show fixture-key --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
# a second key under the same name is a decision, and --replace states it
"$bin" key add fixture-key "$tmp/public.pem" --root "$enrolled_root" > "$tmp/out"
openssl genpkey -algorithm ED25519 -out "$tmp/other-private.pem" > /dev/null 2> "$tmp/err"
openssl pkey -in "$tmp/other-private.pem" -pubout -out "$tmp/other-public.pem" > /dev/null 2> "$tmp/err"
if "$bin" key add fixture-key "$tmp/other-public.pem" --root "$enrolled_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -q 'decision-required key=fixture-key' "$tmp/err"
"$bin" key add fixture-key "$tmp/other-public.pem" --root "$enrolled_root" --replace > "$tmp/out"
grep -q 'replaced enrolled$' "$tmp/out"
mkdir -p "$tmp/image/inputs" "$tmp/image/work" "$tmp/image-source" "$tmp/image-root"
cp "$tmp/signed-config" "$tmp/image-source/sources.conf"
printf 'fixture\n' > "$tmp/image-source/aliases"
printf '%s\n' "$index" > "$tmp/image-source/fixture.index"
printf '%s\n' "$signed_commit" > "$tmp/image-source/fixture.commit"
: > "$tmp/image/build.record"
"$bin" db init --root "$tmp/image-root" > "$tmp/out"
sh tools/image-source-stage.sh "$bin" "$tmp/image-root" "$tmp/image" "$tmp/image-source" > "$tmp/out"
grep -qx "source-commit fixture $signed_commit" "$tmp/image/build.record"
"$bin" source catalog bind fixture "$tmp/image/mirrors/fixture" --root "$tmp/image-root" > "$tmp/out"
"$bin" search git-fixture --source fixture --root "$tmp/image-root" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
mkdir "$tmp/limine"
for input in kernel static-holypkg static-holyinstall static-cc busybox dinit mdevd; do : > "$tmp/$input"; done
cat > "$tmp/image.conf" <<EOF
[image]
arch x86_64
output "$tmp/iso-output"
kernel-image "$tmp/kernel"
kernel-version fixture
limine-dir "$tmp/limine"
static-holypkg "$tmp/static-holypkg"
static-holyinstall "$tmp/static-holyinstall"
static-cc "$tmp/static-cc"
profile static-core
root-storage ram
boot-test build-only
[packages]
busybox "$tmp/busybox"
dinit "$tmp/dinit"
mdevd "$tmp/mdevd"
add fixture:git-fixture
[source fixture]
type holy-git
url "file://$tmp/repo"
index-sha256 "$index"
commit "$signed_commit"
trust require
public-key "$tmp/public.pem"
[docs]
include installed-man-pages
output /usr/share/holy/llm.txt
EOF
./holygetiso --check "$tmp/image.conf" > "$tmp/out"
grep -qx "source fixture index $index" "$tmp/out"
mkdir "$tmp/fetched"
"$bin" fetch fixture:git-fixture --root "$tmp/root" --output "$tmp/fetched" > "$tmp/out"
test -f "$tmp/fetched/$(sha256sum "$tmp/repo/fixture.holy" | cut -d ' ' -f 1).holy"
"$bin" source list --root "$tmp/root" > "$tmp/out"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/out")
test "${#source_id}" -eq 64
catalog="$tmp/root/var/cache/holypkg/catalogs/$source_id/$index"
test "$(cat "$catalog/git-commit")" = "$commit"
grep -qx "source-id $source_id" "$catalog/mirror-origin"
if "$bin" sync fixture --root "$tmp/root" --sha256 "$index" --commit "$(printf '%040d' 0)" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" sync fixture --root "$tmp/root" --sha256 "$(printf '%064d' 0)" --commit "$commit" --output "$tmp/bad" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" sync fixture --root "$tmp/root" --commit "$commit" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cp "$catalog/git-commit" "$tmp/saved-commit"
printf '%040d\n' 0 > "$catalog/git-commit"
if "$bin" search git-fixture --source fixture --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cp "$tmp/saved-commit" "$catalog/git-commit"
"$bin" search git-fixture --source fixture --root "$tmp/root" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
