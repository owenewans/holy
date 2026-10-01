#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share" "$tree"
db="$root/var/lib/holypkg"
expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
service_package() {
    name=$1
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share" "$tree/DATA/etc/dinit.d"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf '%s\n' "$name" > "$tree/DATA/usr/share/$name"
    printf 'type = process\ncommand = /usr/bin/%s\n' "$name" > "$tree/DATA/etc/dinit.d/$name"
    mkdir -p "$tree/DATA/usr/lib/holy-units"
    printf 'type = process\n' > "$tree/DATA/usr/lib/holy-units/$name"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
}
package() {
    name=$1 path=$2 dependency=$3
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "${4:-$name}" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$name" > "$tree/DATA/usr/share/$path"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
"$bin" db init --root "$root" > "$tmp/out"
package app app lib
package lib lib ''
package unused unused ''
app=$(hash app) lib=$(hash lib) unused=$(hash unused)
package alternative alternative '' lib
alternative=$(hash alternative)
expect 3 "$bin" db plan-set "$app" "$lib" "$alternative" --root "$root"
expect 0 "$bin" db plan-set "$app" "$lib" "$alternative" --choose "dep-1=$lib" --root "$root"
chosen=$(plan_hash)
expect 3 "$bin" db apply-set "$chosen" "$app" "$lib" --root "$root"
test ! -e "$root/usr/share/app"
expect 4 "$bin" db plan-set "$app" --root "$root"
expect 0 "$bin" db plan-set "$app" "$lib" "$unused" --root "$root"
plan=$(plan_hash)
test "${#plan}" -eq 64
grep -qx "selected $app app explicit" "$tmp/out"
grep -qx "selected $lib lib dependency" "$tmp/out"
# a selection where nothing is offered twice states that with one summary line
grep -qx "set-conflicts generation 0 artifacts 2 capabilities 0 conflicts 0 read-only" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 5
test "$(cat "$db/generation")" -eq 0
test ! -e "$root/usr/share/app"
expect 0 "$bin" db plan-set "$app" "$unused" "$lib" --root "$root"
test "$(plan_hash)" = "$plan"
expect 3 "$bin" db apply-set "$(printf '%064d' 0)" "$app" "$lib" --root "$root"
test ! -e "$db/transactions/set-journal"
test ! -e "$root/usr/share/app"
printf '2\n' > "$db/generation"
expect 3 "$bin" db apply-set "$plan" "$app" "$lib" "$unused" --root "$root"
test ! -e "$root/usr/share/app"
printf '0\n' > "$db/generation"
expect 0 "$bin" db apply-set "$plan" "$app" "$lib" "$unused" --root "$root"
grep -qx "committed-set $plan generation 1 artifacts 2" "$tmp/out"
test "$(cat "$db/generation")" -eq 1
grep -qx app "$root/usr/share/app"
grep -qx lib "$root/usr/share/lib"
test ! -e "$root/usr/share/unused"
grep -qx 'reason explicit' "$db/installed/$app/state"
grep -qx 'reason dependency' "$db/installed/$lib/state"
cmp "$db/installed/$app/graph" "$db/installed/$lib/graph"
grep -Fqx "edge \"$app\" \"dep-1\" \"$lib\" \"-\" \"package\" \"lib\"" "$db/installed/$app/graph"
expect 0 "$bin" db status --root "$root"
expect 0 "$bin" db check --all --root "$root"
expect 3 "$bin" db rm "$lib" --root "$root"
test -f "$root/usr/share/lib"
test "$(cat "$db/generation")" -eq 1
cp -a "$root" "$tmp/broken-root"
cp -a "$root" "$tmp/broken-recover"
cp -a "$root" "$tmp/broken-fault"
cp -a "$root" "$tmp/broken-retired"
cat > "$tmp/remove-fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int unlinkat(int dir, const char *path, int flags)
{
    int (*actual)(int, const char *, int);
    void *symbol = dlsym(RTLD_NEXT, "unlinkat");
    memcpy(&actual, &symbol, sizeof actual);
    if (!actual) abort();
    if ((getenv("HOLY_FAIL_JOURNAL") && !strcmp(path, "journal")) ||
        (!getenv("HOLY_FAIL_JOURNAL") && !getenv("HOLY_FAIL_RETIRED") &&
         !strcmp(path, "lib"))) {
        errno = ENOSPC; return -1;
    }
    return actual(dir, path, flags);
}
int renameat(int olddir, const char *oldpath, int newdir, const char *newpath)
{
    int (*actual)(int, const char *, int, const char *);
    void *symbol = dlsym(RTLD_NEXT, "renameat");
    memcpy(&actual, &symbol, sizeof actual);
    if (!actual) abort();
    if (getenv("HOLY_FAIL_RETIRED") && !strcmp(newpath, "old-instance")) {
        int result = actual(olddir, oldpath, newdir, newpath);
        if (result == 0) { errno = ENOSPC; return -1; }
        return result;
    }
    return actual(olddir, oldpath, newdir, newpath);
}
C
gcc -shared -fPIC -o "$tmp/remove-fault.so" "$tmp/remove-fault.c" -ldl
expect 5 env LD_PRELOAD="$tmp/remove-fault.so" "$bin" db rm "$lib" --accept-broken --root "$tmp/broken-fault"
grep -qx 'plan 0000000000000000000000000000000000000000000000000000000000000001' \
    "$tmp/broken-fault/var/lib/holypkg/transactions/journal"
expect 0 "$bin" db recover --continue --root "$tmp/broken-fault"
expect 4 "$bin" db check "$app" --root "$tmp/broken-fault" --json
grep -Rqx 'accept-broken yes' "$tmp/broken-fault/var/lib/holypkg/transactions"/*/decisions
expect 5 env HOLY_FAIL_RETIRED=1 LD_PRELOAD="$tmp/remove-fault.so" \
    "$bin" db rm "$lib" --accept-broken --root "$tmp/broken-retired"
test ! -e "$tmp/broken-retired/var/lib/holypkg/installed/$lib"
test "$(cat "$tmp/broken-retired/var/lib/holypkg/generation")" -eq 1
test -f "$tmp/broken-retired/var/lib/holypkg/transactions"/*/old-instance/files
expect 5 "$bin" db status --root "$tmp/broken-retired"
expect 0 "$bin" db recover --continue --root "$tmp/broken-retired"
expect 4 "$bin" db check "$app" --root "$tmp/broken-retired" --json
grep -Rqx 'accept-broken yes' "$tmp/broken-retired/var/lib/holypkg/transactions"/*/decisions
printf 'format holy-journal-1\nstage removing\ngeneration 1\nartifact %s\nplan %064d\n' \
    "$lib" 1 > "$tmp/broken-recover/var/lib/holypkg/transactions/journal"
rm "$tmp/broken-recover/usr/share/lib"
expect 5 "$bin" db status --root "$tmp/broken-recover"
expect 0 "$bin" db recover --continue --root "$tmp/broken-recover"
expect 4 "$bin" db check "$app" --root "$tmp/broken-recover" --json
grep -q '"code":"broken-provider"' "$tmp/out"
grep -Rqx 'accept-broken yes' "$tmp/broken-recover/var/lib/holypkg/transactions"/*/decisions
cp -a "$root" "$tmp/broken-after-generation"
expect 5 env HOLY_FAIL_JOURNAL=1 LD_PRELOAD="$tmp/remove-fault.so" \
    "$bin" db rm "$lib" --accept-broken --root "$tmp/broken-after-generation"
test "$(cat "$tmp/broken-after-generation/var/lib/holypkg/generation")" -eq 2
expect 5 "$bin" db status --root "$tmp/broken-after-generation"
expect 0 "$bin" db recover --continue --root "$tmp/broken-after-generation"
expect 4 "$bin" db check "$app" --root "$tmp/broken-after-generation" --json
grep -Rqx 'accept-broken yes' "$tmp/broken-after-generation/var/lib/holypkg/transactions"/*/decisions
expect 0 "$bin" db rm "$lib" --accept-broken --root "$tmp/broken-root"
test ! -e "$tmp/broken-root/usr/share/lib"
test -f "$tmp/broken-root/usr/share/app"
expect 4 "$bin" db check "$app" --root "$tmp/broken-root" --json
grep -q '"code":"broken-provider"' "$tmp/out"
grep -Rqx 'accept-broken yes' "$tmp/broken-root/var/lib/holypkg/transactions"/*/decisions
cp -a "$tmp/broken-root" "$tmp/broken-record-tamper"
for decision in "$tmp/broken-record-tamper/var/lib/holypkg/transactions"/*/decisions; do
    printf 'accept-broken no\n' > "$decision"
    break
done
expect 1 "$bin" db status --root "$tmp/broken-record-tamper"
expect 0 "$bin" db plan-set "$lib" --root "$tmp/broken-root"
broken_plan=$(plan_hash)
expect 0 "$bin" db apply-set "$broken_plan" "$lib" --root "$tmp/broken-root"
expect 0 "$bin" db check --all --root "$tmp/broken-root"
expect 0 "$bin" db rm "$app" --root "$tmp/broken-root"
grep -Rqx 'accept-broken no' "$tmp/broken-root/var/lib/holypkg/transactions"/*/decisions
journal() {
    printf 'format holy-set-journal-1\ngeneration 0\nplan %s\nroot %s\nchoice -\n' "$plan" "$app"
    printf '%s\n' "$app" "$lib" | sort | sed 's/^/artifact /'
}
journal > "$db/transactions/set-journal"
chmod 600 "$db/transactions/set-journal"
expect 5 "$bin" db status --root "$root"
cp "$db/installed/$lib/files" "$tmp/installed-files"
: > "$db/installed/$lib/files"
expect 5 "$bin" db recover --finish-set --root "$root"
mv "$tmp/installed-files" "$db/installed/$lib/files"
printf broken > "$root/usr/share/lib"
expect 5 "$bin" db recover --finish-set --root "$root"
test -f "$db/transactions/set-journal"
printf 'lib\n' > "$root/usr/share/lib"
expect 0 "$bin" db recover --finish-set --root "$root"
test ! -e "$db/transactions/set-journal"
test "$(cat "$db/generation")" -eq 1
journal > "$db/transactions/set-journal"
chmod 600 "$db/transactions/set-journal"
printf '0\n' > "$db/generation"
expect 0 "$bin" db recover --finish-set --root "$root"
test "$(cat "$db/generation")" -eq 1
expect 0 "$bin" db rm "$app" --root "$root"
expect 0 "$bin" db rm "$lib" --root "$root"
test "$(cat "$db/generation")" -eq 3
package collision app ''
collision=$(hash collision)
# the selected provider also collides with its consumer.
rm "$tmp/app.holy"
package app collision collision
app=$(hash app)
expect 0 "$bin" db plan-set "$app" "$collision" --root "$root"
rm "$tmp/collision.holy"
package collision collision ''
collision=$(hash collision)
expect 4 "$bin" db plan-set "$app" "$collision" --root "$root"
test ! -e "$root/usr/share/collision"
rm "$tmp/app.holy"
package app app lib
app=$(hash app)
expect 0 "$bin" db plan-set "$app" "$lib" --root "$root"
plan=$(plan_hash)
second=$(printf '%s\n' "$app" "$lib" | sort | tail -1)
if test "$second" = "$app"; then target=app; first=$lib; else target=lib; first=$app; fi
cat > "$tmp/fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
/* the binary is built with _FILE_OFFSET_BITS=64, so it calls openat64 */
int openat64(int dir, const char *path, int flags, ...)
{
    static int (*real_openat)(int, const char *, int, ...);
    mode_t mode = 0;
    const char *fail = getenv("HOLY_FAIL_PATH");
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!real_openat) {
        void *symbol = dlsym(RTLD_NEXT, "openat64");
        memcpy(&real_openat, &symbol, sizeof real_openat);
        if (!real_openat) abort();
    }
    if ((flags & O_CREAT) && fail && !strcmp(path, fail)) { errno = ENOSPC; return -1; }
    return real_openat(dir, path, flags, mode);
}
C
gcc -shared -fPIC -o "$tmp/fault.so" "$tmp/fault.c" -ldl
expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH="$target" "$bin" db apply-set "$plan" "$app" "$lib" --root "$root"
test -f "$db/transactions/set-journal"
test -f "$db/installed/$first/state"
test ! -e "$db/installed/$second"
test "$(cat "$db/generation")" -eq 3
expect 5 "$bin" db status --root "$root"
expect 5 "$bin" db check --all --root "$root" --json
grep -q '"code":"incomplete-transaction","status":5' "$tmp/out"
expect 5 "$bin" db rm "$first" --root "$root"
expect 5 "$bin" db recover --finish-set --root "$root"
# an unrecorded partial payload requires inspection, not silent overwriting.
printf partial > "$root/usr/share/$target"
expect 5 "$bin" db recover --continue-set --root "$root"
grep -qx partial "$root/usr/share/$target"
rm "$root/usr/share/$target"
expect 0 "$bin" db recover --continue-set --root "$root"
grep -qx "resumed $second" "$tmp/out"
test "$(cat "$db/generation")" -eq 4
expect 0 "$bin" db check --all --root "$root"
test ! -e "$db/transactions/set-journal"
rm "$root/usr/share/app"
expect 0 "$bin" db repair-plan "$app" --root "$root"
repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
test "${#repair}" -eq 64
expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH=app "$bin" db repair "$app" --plan "$repair" --root "$root"
grep -qx 'stage repairing' "$db/transactions/journal"
expect 5 "$bin" db status --root "$root"
expect 5 "$bin" db recover --continue --root "$root"
printf partial > "$root/usr/share/app"
expect 5 "$bin" db recover --repair --root "$root"
grep -qx partial "$root/usr/share/app"
rm "$root/usr/share/app"
expect 0 "$bin" db recover --repair --root "$root"
test "$(cat "$db/generation")" -eq 5
test ! -e "$db/transactions/journal"
grep -qx app "$root/usr/share/app"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db rm "$app" --root "$root"
cp "$db/installed/$lib/state" "$tmp/provider-state"
cp "$db/installed/$lib/graph" "$tmp/provider-graph"
inode=$(stat -c '%i:%Y' "$root/usr/share/lib")
expect 0 "$bin" db plan-set "$app" --root "$root"
plan=$(plan_hash)
grep -qx "selected $lib lib installed" "$tmp/out"
printf damaged > "$root/usr/share/lib"
expect 4 "$bin" db apply-set "$plan" "$app" --root "$root"
test ! -e "$root/usr/share/app"
printf 'lib\n' > "$root/usr/share/lib"
inode=$(stat -c '%i:%Y' "$root/usr/share/lib")
sed 's/reason dependency/reason explicit/' "$tmp/provider-state" > "$db/installed/$lib/state"
expect 3 "$bin" db apply-set "$plan" "$app" --root "$root"
cp "$tmp/provider-state" "$db/installed/$lib/state"
mv "$root/var/cache/holypkg/objects/sha256/$lib.holy" "$tmp/provider-cache"
expect 6 "$bin" db plan-set "$app" --root "$root"
mv "$tmp/provider-cache" "$root/var/cache/holypkg/objects/sha256/$lib.holy"
expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH=app "$bin" db apply-set "$plan" "$app" --root "$root"
test "$(cat "$db/generation")" -eq 6
printf damaged > "$root/usr/share/lib"
expect 5 "$bin" db recover --continue-set --root "$root"
printf 'lib\n' > "$root/usr/share/lib"
inode=$(stat -c '%i:%Y' "$root/usr/share/lib")
expect 0 "$bin" db recover --continue-set --root "$root"
test "$(cat "$db/generation")" -eq 7
test "$(stat -c '%i:%Y' "$root/usr/share/lib")" = "$inode"
cmp "$tmp/provider-state" "$db/installed/$lib/state"
cmp "$tmp/provider-graph" "$db/installed/$lib/graph"
expect 0 "$bin" db check --all --root "$root"
expect 3 "$bin" db rm "$lib" --root "$root"
expect 0 "$bin" db plan-set "$unused" --root "$root"
unused_plan=$(plan_hash)
expect 0 "$bin" db apply-set "$unused_plan" "$unused" --root "$root"
rm "$root/var/cache/holypkg/objects/sha256/$unused.holy"
expect 0 "$bin" db rm "$app" --root "$root"
expect 0 "$bin" db plan-set "$app" --root "$root"
grep -qx "selected $lib lib installed" "$tmp/out"
# a unit below the boot services directory is a service dinit starts on its own, so a set
# that ships one needs a consent naming it, and a unit kept outside that directory is
# not one and needs nothing
service_package service-fixture
service=$(sha256sum "$tmp/service-fixture.holy" | cut -d ' ' -f 1)
expect 3 "$bin" db plan-set "$service" --root "$root"
grep -qx "holypkg: $service ships the service unit /etc/dinit.d/service-fixture; a set that starts a service needs --accept-service service-fixture" "$tmp/err"
test ! -e "$root/etc/dinit.d/service-fixture"
expect 2 "$bin" db plan-set "$service" --accept-service ../escape --root "$root"
expect 2 "$bin" db plan-set "$service" --accept-service "" --root "$root"
expect 2 "$bin" db plan-set "$service" --accept-service service-fixture --accept-service service-fixture --root "$root"
expect 0 "$bin" db plan-set "$service" --accept-service service-fixture --root "$root"
grep -qx "service $service service-fixture path /etc/dinit.d/service-fixture state starts-at-next-boot" "$tmp/out"
test "$(grep -c '^service ' "$tmp/out")" -eq 1
service_plan=$(plan_hash)
expect 3 "$bin" db apply-set "$service_plan" "$service" --root "$root"
expect 0 "$bin" db apply-set "$service_plan" "$service" --accept-service service-fixture --root "$root"
test -f "$root/etc/dinit.d/service-fixture"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db rm "$service" --root "$root"
test ! -e "$root/etc/dinit.d/service-fixture"
# the consent is a journal decision, so an interrupted set carries it into recovery
expect 0 "$bin" db plan-set "$service" --accept-service service-fixture --root "$root"
fault_plan=$(plan_hash)
expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_FAIL_PATH=service-fixture \
    "$bin" db apply-set "$fault_plan" "$service" --accept-service service-fixture --root "$root"
test -f "$db/transactions/set-journal"
grep -qx 'service service-fixture' "$db/transactions/set-journal"
expect 5 "$bin" db status --root "$root"
expect 0 "$bin" db recover --continue-set --root "$root"
test -f "$root/etc/dinit.d/service-fixture"
test ! -e "$db/transactions/set-journal"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db rm "$service" --root "$root"
# the root keeps what every committed transaction was reviewed with, and reports the
# records as they state themselves
expect 0 "$bin" db transactions --root "$root"
test "$(grep -c '^transaction ' "$tmp/out")" -eq 12
grep -qx "summary transactions 12 read-only" "$tmp/out"
test "$(grep -c '^transaction .* kind set ' "$tmp/out")" -eq 6
test "$(grep -c '^transaction .* kind remove ' "$tmp/out")" -eq 6
grep -qx "transaction $fault_plan kind set generation 11 artifacts 1 decisions 2" "$tmp/out"
grep -qx "transaction-decision $fault_plan service service-fixture" "$tmp/out"
grep -qx "transaction-decision $service_plan artifact $service" "$tmp/out"
grep -qx "transaction-decision $service_plan service service-fixture" "$tmp/out"
test "$(grep -c "^transaction-decision $service_plan " "$tmp/out")" -eq 2
test "$(grep -c '^transaction-decision .* accept-broken no$' "$tmp/out")" -eq 6
expect 0 "$bin" db transactions --root "$root" --json
grep -q '"schema":"holy-transactions-1","type":"summary"' "$tmp/out"
test "$(grep -c '"type":"transaction"' "$tmp/out")" -eq 12
grep -qx "{\"schema\":\"holy-transactions-1\",\"type\":\"transaction\",\"identity\":\"$service_plan\",\"kind\":\"set\",\"facts\":\"generation 9 artifacts 1\",\"decisions\":2}" "$tmp/out"
expect 6 "$bin" db transactions --root "$tmp/empty"
grep -qx 'holypkg: database unavailable' "$tmp/err"
printf 'package set fixtures passed\n'
