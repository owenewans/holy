#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root space"
tree="$tmp/tree"
mkdir -p "$root/usr/bin" "$tree/HOLY" "$tree/DATA/usr/bin"
cat > "$tmp/runner.c" <<'EOF'
#include <stdio.h>
int main(int argc, char **argv)
{
    if (argc != 3) return 31;
    printf("%s:%s:%s\n", argv[0], argv[1], argv[2]);
    return 17;
}
EOF
${FIXTURE_CC:-gcc} -static -o "$tree/DATA/usr/bin/runner" "$tmp/runner.c"
printf 'format holy-package-1\nname runner\nversion 1\nrelease 1\nos linux\narch x86_64\nlibc nolibc\n' > "$tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
"$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
mv "$tmp/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$tmp/runner.holy" > "$tmp/out"
digest=$(sha256sum "$tmp/runner.holy" | cut -d ' ' -f 1)
"$bin" db init --root "$root" > "$tmp/out"
"$bin" cache stage "local:$tmp/runner.holy" --root "$root" > "$tmp/out"
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\n' > "$tmp/source.conf"
"$bin" source plan --config "$tmp/source.conf" --root "$root" > "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
"$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root" > "$tmp/out"
"$bin" source list --root "$root" > "$tmp/source.list"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/source.list")
test "${#source_id}" -eq 64
"$bin" db plan-set "$digest" --source "$digest=$source_id" --root "$root" > "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db apply-set "$plan" "$digest" --source "$digest=$source_id" --root "$root" > "$tmp/out"
if "$bin" run fixture:runner --root "$root" -- runner first second > "$tmp/out"; then exit 1; else test "$?" -eq 17; fi
grep -qx 'runner:first:second' "$tmp/out"
viewroot="$tmp/viewroot"
viewtree="$tmp/viewtree"
mkdir -p "$viewroot/usr/bin" "$viewtree/HOLY" "$viewtree/DATA/usr/bin" \
    "$viewtree/DATA/usr/lib/holy/private/fixture/usr/bin" \
    "$viewtree/DATA/usr/lib/holy/private/fixture/usr/lib/app-context" \
    "$viewroot/usr/lib/app-context" "$viewroot/app"
cat > "$tmp/view-helper.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 32;
    printf("private helper:%s:%ld\n", argv[1], (long)geteuid());
    return 23;
}
EOF
cat > "$tmp/view-runner.c" <<'EOF'
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 32;
    argv[0] = "/usr/bin/helper";
    execv(argv[0], argv);
    return 31;
}
EOF
cat > "$tmp/path-runner.c" <<'EOF'
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 32;
    argv[0] = "helper";
    execvp(argv[0], argv);
    return 31;
}
EOF
cat > "$tmp/dir-runner.c" <<'EOF'
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 32;
    argv[0] = "/usr/lib/app-context/helper";
    execv(argv[0], argv);
    return 31;
}
EOF
sed 's|/usr/lib/app-context/helper|/app/helper|' "$tmp/dir-runner.c" > "$tmp/app-runner.c"
sed 's/private helper/public helper/; s/return 23/return 24/' "$tmp/view-helper.c" > "$tmp/public-helper.c"
${FIXTURE_CC:-gcc} -static -o "$viewroot/usr/bin/helper" "$tmp/public-helper.c"
${FIXTURE_CC:-gcc} -static -o "$viewtree/DATA/usr/lib/holy/private/fixture/usr/bin/helper" "$tmp/view-helper.c"
${FIXTURE_CC:-gcc} -static -o "$viewtree/DATA/usr/bin/runner" "$tmp/view-runner.c"
${FIXTURE_CC:-gcc} -static -o "$viewtree/DATA/usr/bin/path-runner" "$tmp/path-runner.c"
${FIXTURE_CC:-gcc} -static -o "$viewtree/DATA/usr/bin/dir-runner" "$tmp/dir-runner.c"
${FIXTURE_CC:-gcc} -static -o "$viewtree/DATA/usr/bin/app-runner" "$tmp/app-runner.c"
cp "$viewtree/DATA/usr/lib/holy/private/fixture/usr/bin/helper" \
    "$viewtree/DATA/usr/lib/holy/private/fixture/usr/lib/app-context/helper"
cp "$viewroot/usr/bin/helper" "$viewroot/usr/lib/app-context/helper"
cp "$viewroot/usr/bin/helper" "$viewroot/app/helper"
printf 'format holy-package-1\nname view-runner\nversion 1\nrelease 1\nos linux\narch x86_64\nlibc nolibc\n' > "$viewtree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$viewtree/HOLY/$field"; done
"$bin" manifest generate "$viewtree" --output "$tmp/view-files" > "$tmp/out"
mv "$tmp/view-files" "$viewtree/HOLY/files"
"$bin" pack "$viewtree" --output "$tmp/view-runner.holy" > "$tmp/out"
viewdigest=$(sha256sum "$tmp/view-runner.holy" | cut -d ' ' -f 1)
"$bin" db init --root "$viewroot" > "$tmp/out"
"$bin" cache stage "local:$tmp/view-runner.holy" --root "$viewroot" > "$tmp/out"
"$bin" db plan-set "$viewdigest" --root "$viewroot" > "$tmp/out"
viewplan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db apply-set "$viewplan" "$viewdigest" --root "$viewroot" > "$tmp/out"
if "$bin" run local:view-runner --root "$viewroot" -- path-runner example > "$tmp/out"; then exit 1; else test "$?" -eq 23; fi
grep -qx "private helper:example:$(id -u)" "$tmp/out"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /app=/usr/lib/holy/private/fixture/usr/lib/app-context \
    -- app-runner example > "$tmp/out"; then exit 1; else test "$?" -eq 23; fi
grep -qx "private helper:example:$(id -u)" "$tmp/out"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /usr/lib/app-context=/usr/lib/holy/private/fixture/usr/lib/app-context \
    -- dir-runner example > "$tmp/out"; then exit 1; else test "$?" -eq 23; fi
grep -qx "private helper:example:$(id -u)" "$tmp/out"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /usr/bin/helper=/usr/lib/holy/private/fixture/usr/bin/helper \
    -- runner example > "$tmp/out"; then exit 1; else test "$?" -eq 23; fi
grep -qx "private helper:example:$(id -u)" "$tmp/out"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /usr/bin/helper=/usr/lib/holy/private/fixture/usr/bin/missing \
    -- runner example > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
if "$bin" run local:view-runner --root "$viewroot" \
    --view /usr/bin/helper=/usr/lib/holy/private/fixture/usr/lib/app-context \
    -- runner example > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
mkdir -p "$viewroot/usr/lib/holy/private/fixture/unowned"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /app=/usr/lib/holy/private/fixture/unowned \
    -- app-runner example > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
ln -s ../bin "$viewroot/usr/lib/host-link"
if "$bin" run local:view-runner --root "$viewroot" \
    --view /usr/lib/host-link/helper=/usr/lib/holy/private/fixture/usr/bin/helper \
    -- runner example > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
if "$viewroot/usr/bin/helper" example > "$tmp/out"; then exit 1; else test "$?" -eq 24; fi
grep -qx "public helper:example:$(id -u)" "$tmp/out"
if "$bin" run fixture:runner --root "$root" -- /usr/bin/runner first second > "$tmp/out"; then exit 1; else test "$?" -eq 17; fi
grep -qx '/usr/bin/runner:first:second' "$tmp/out"
if "$bin" run fixture:runner --root "$root" -- missing first second > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
printf 'changed\n' >> "$root/usr/bin/runner"
if "$bin" run fixture:runner --root "$root" -- runner first second > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
local_root="$tmp/local root"
mkdir -p "$local_root/usr/bin"
"$bin" db init --root "$local_root" > "$tmp/out"
"$bin" cache stage "local:$tmp/runner.holy" --root "$local_root" > "$tmp/out"
"$bin" db plan-set "$digest" --root "$local_root" > "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db apply-set "$plan" "$digest" --root "$local_root" > "$tmp/out"
if "$bin" run local:runner --root "$local_root" -- runner first second > "$tmp/out"; then exit 1; else test "$?" -eq 17; fi
grep -qx 'runner:first:second' "$tmp/out"
