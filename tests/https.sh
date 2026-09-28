#!/bin/sh
set -eu

no_proxy=localhost,127.0.0.1
NO_PROXY=$no_proxy
export no_proxy NO_PROXY

bin=$1
tmp=$(mktemp -d)
server=
trap 'if test -n "$server"; then kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :; fi; rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/serve/HOLY" "$tmp/serve/DATA" "$tmp/out"
cat > "$tmp/serve/HOLY/meta" <<'EOF'
format holy-package-1
name https-fixture
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for field in files deps provides hooks origin transform; do
    : > "$tmp/serve/HOLY/$field"
done
tar -cf "$tmp/native.tar" -C "$tmp/serve" HOLY DATA
lz4 -q "$tmp/native.tar" "$tmp/serve/native.holy"
digest=$(sha256sum "$tmp/serve/native.holy")
digest=${digest%% *}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    > "$tmp/openssl.log" 2>&1
mkfifo "$tmp/port"
python3 -u -c '
import http.server, os, ssl, sys
os.chdir(sys.argv[1])
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redirect/") or self.path in ("/redirect.holy", "/credential.holy", "/credential/current"):
            userinfo = "user:pass@" if self.path.startswith("/credential") else ""
            target = self.path[len("/redirect/"):] if self.path.startswith("/redirect/") else (
                "current" if self.path.endswith("/current") else "native.holy")
            self.send_response(302)
            self.send_header("Location", f"https://{userinfo}localhost:{self.server.server_port}/{target}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return super().do_GET()
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
' "$tmp/serve" "$tmp/cert.pem" "$tmp/key.pem" > "$tmp/port" 2> "$tmp/server.log" &
server=$!
read -r port < "$tmp/port"
test -n "$port"
expect() {
    wanted=$1
    shift
    rc=0
    "$@" > "$tmp/result" 2> "$tmp/error" || rc=$?
    test "$rc" -eq "$wanted" || { cat "$tmp/result" "$tmp/error"; exit 1; }
}
base="https://localhost:$port/"
# build a second output whose filename requires URL escaping.
sed 's/name https-fixture/name https-second/' "$tmp/serve/HOLY/meta" > "$tmp/meta"
mv "$tmp/meta" "$tmp/serve/HOLY/meta"
printf 'require parent https-second package https-fixture any any any - https-fixture fixture\n' > "$tmp/serve/HOLY/deps"
tar -cf "$tmp/second.tar" -C "$tmp/serve" HOLY DATA
lz4 -q "$tmp/second.tar" "$tmp/serve/space?#.holy"
"$bin" repo index "$tmp/serve" > "$tmp/result"
"$bin" repo seal "$tmp/serve" > "$tmp/result"
index=$(sed -n 's/^sha256 //p' "$tmp/serve/current")
expect 0 "$bin" repo mirror "$base" --sha256 "$index" --output "$tmp/mirror" --ca-file "$tmp/cert.pem"
test "$(cat "$tmp/result")" = "sealed $index"
cmp "$tmp/serve/current" "$tmp/mirror/current"
cmp "$tmp/serve/index.$index" "$tmp/mirror/index.$index"
cmp "$tmp/serve/space?#.holy" "$tmp/mirror/space?#.holy"
grep -qx 'verification digest-pinned-unsigned' "$tmp/mirror/mirror-origin"
mkdir "$tmp/source-root"
expect 0 "$bin" db init --root "$tmp/source-root"
printf '[source fixture]\ntype holy-http\nurl "%s"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
expect 0 "$bin" source list --root "$tmp/source-root"
source_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/result")
test "${#source_id}" -eq 64
expect 0 "$bin" sync fixture --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-mirror" --ca-file "$tmp/cert.pem"
grep -qx "source-id $source_id" "$tmp/source-mirror/mirror-origin"
cmp "$tmp/serve/current" "$tmp/source-mirror/current"
expect 0 "$bin" source catalog bind fixture "$tmp/source-mirror" --root "$tmp/source-root"
grep -qx "catalog-bound $source_id index $index" "$tmp/result"
binding="$tmp/source-root/var/lib/holypkg/catalogs/$source_id"
test "$(stat -c %a "$binding")" = 600
grep -qx "index $index" "$binding"
expect 0 "$bin" search https-second --source fixture --root "$tmp/source-root"
grep -qx 'listed 1 packages' "$tmp/result"
expect 0 "$bin" info fixture:https-second --root "$tmp/source-root"
grep -q '^package "https-second" ' "$tmp/result"
expect 0 "$bin" search https-second --source fixture --catalog "$tmp/source-mirror" \
    --root "$tmp/source-root"
grep -q '^package "https-second" ' "$tmp/result"
grep -qx 'listed 1 packages' "$tmp/result"
grep -qx "source-id $source_id" "$tmp/result"
expect 0 "$bin" search missing --source fixture --catalog "$tmp/source-mirror" \
    --root "$tmp/source-root"
grep -qx 'listed 0 packages' "$tmp/result"
expect 0 "$bin" info fixture:https-second --catalog "$tmp/source-mirror" \
    --root "$tmp/source-root"
grep -q '^package "https-second" ' "$tmp/result"
grep -qx "source-id $source_id" "$tmp/result"
test "$(wc -l < "$tmp/result")" -eq 2
expect 6 "$bin" info fixture:missing --catalog "$tmp/source-mirror" \
    --root "$tmp/source-root"
test ! -s "$tmp/result"
expect 6 "$bin" search https-second --source wrong --catalog "$tmp/source-mirror" \
    --root "$tmp/source-root"
expect 2 "$bin" info fixture:https-second --bogus --root "$tmp/source-root"
cp -a "$tmp/source-mirror" "$tmp/changed-source-mirror"
printf broken >> "$tmp/changed-source-mirror/native.holy"
expect 6 "$bin" search https-second --source fixture --catalog "$tmp/changed-source-mirror" \
    --root "$tmp/source-root"
expect 6 "$bin" info fixture:https-second --catalog "$tmp/changed-source-mirror" \
    --root "$tmp/source-root"
expect 6 "$bin" source catalog bind fixture "$tmp/changed-source-mirror" \
    --root "$tmp/source-root"
expect 0 "$bin" search https-second --source fixture --root "$tmp/source-root"
cp "$binding" "$tmp/valid-binding"
rm "$binding"
ln -s "$tmp/valid-binding" "$binding"
expect 6 "$bin" search https-second --source fixture --root "$tmp/source-root"
rm "$binding"
cp "$tmp/valid-binding" "$binding"
expect 0 "$bin" search https-second --source fixture --root "$tmp/source-root"
cp "$tmp/source-mirror/current" "$tmp/valid-current"
printf 'sha256 %064d\n' 0 > "$tmp/source-mirror/current"
expect 6 "$bin" info fixture:https-second --root "$tmp/source-root"
cp "$tmp/valid-current" "$tmp/source-mirror/current"
expect 0 "$bin" info fixture:https-second --root "$tmp/source-root"
mkdir "$tmp/add-root"
expect 0 "$bin" db init --root "$tmp/add-root"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/add-root"
cp "$tmp/result" "$tmp/add-source.plan"
add_source_plan=$(sha256sum "$tmp/add-source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/add-source.plan" --sha256 "$add_source_plan" \
    --root "$tmp/add-root"
expect 6 "$bin" add fixture:https-second --root "$tmp/add-root" --yes
expect 0 "$bin" source catalog bind fixture "$tmp/source-mirror" --root "$tmp/add-root"
expect 3 "$bin" add fixture:https-second --root "$tmp/add-root" < /dev/null
grep -q 'plan-set .* read-only' "$tmp/result"
test "$(cat "$tmp/add-root/var/lib/holypkg/generation")" -eq 0
expect 0 "$bin" add fixture:https-second --root "$tmp/add-root" --yes
second_hash=$(sha256sum "$tmp/serve/space?#.holy" | cut -d ' ' -f 1)
grep -qx "source-id $source_id" "$tmp/add-root/var/lib/holypkg/installed/$digest/state"
grep -qx "source-id $source_id" "$tmp/add-root/var/lib/holypkg/installed/$second_hash/state"
expect 0 "$bin" db check --all --root "$tmp/add-root"
if readelf -l "$bin" | grep -q INTERP; then
    mkdir "$tmp/fault-root"
    expect 0 "$bin" db init --root "$tmp/fault-root"
    expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/fault-root"
    cp "$tmp/result" "$tmp/fault-source.plan"
    fault_source_plan=$(sha256sum "$tmp/fault-source.plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/fault-source.plan" --sha256 "$fault_source_plan" \
        --root "$tmp/fault-root"
    cat > "$tmp/fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
int renameat(int olddir, const char *oldpath, int newdir, const char *newpath)
{
    int (*real_renameat)(int, const char *, int, const char *);
    void *symbol = dlsym(RTLD_NEXT, "renameat");
    memcpy(&real_renameat, &symbol, sizeof real_renameat);
    if (!real_renameat) abort();
    if (!strcmp(newpath, "generation")) { errno = ENOSPC; return -1; }
    return real_renameat(olddir, oldpath, newdir, newpath);
}
C
    gcc -shared -fPIC -o "$tmp/fault.so" "$tmp/fault.c" -ldl
    expect 5 env LD_PRELOAD="$tmp/fault.so" "$bin" add fixture:https-second \
        --catalog "$tmp/source-mirror" --root "$tmp/fault-root" --yes
    journal="$tmp/fault-root/var/lib/holypkg/transactions/set-journal"
    grep -qx 'format holy-set-journal-5' "$journal"
    grep -qx "catalog-index $index" "$journal"
    grep -qx "binding $digest=$source_id" "$journal"
    grep -qx "binding $second_hash=$source_id" "$journal"
    cp "$journal" "$tmp/valid-journal"
    sed "s/catalog-index $index/catalog-index $(printf '%064d' 0)/" \
        "$tmp/valid-journal" > "$journal"
    expect 5 "$bin" db recover --finish-set --root "$tmp/fault-root"
    cp "$tmp/valid-journal" "$journal"
    expect 0 "$bin" db recover --finish-set --root "$tmp/fault-root"
    expect 0 "$bin" db check --all --root "$tmp/fault-root"
fi
mkdir "$tmp/fetched"
expect 0 "$bin" fetch fixture:https-fixture --output "$tmp/fetched" \
    --root "$tmp/source-root"
grep -Fxq "$tmp/fetched/$digest.holy" "$tmp/result"
expect 0 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
grep -Fxq "$tmp/fetched/$digest.holy" "$tmp/result"
cmp "$tmp/serve/native.holy" "$tmp/fetched/$digest.holy"
expect 0 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --extract --output "$tmp/extracted" --root "$tmp/source-root"
grep -qx 'name https-fixture' "$tmp/extracted/HOLY/meta"
expect 6 "$bin" fetch fixture:missing --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
expect 6 "$bin" fetch absent:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
cp "$tmp/source-mirror/mirror-origin" "$tmp/valid-origin"
sed "s/$source_id/$(printf '%064d' 0)/" "$tmp/valid-origin" > "$tmp/source-mirror/mirror-origin"
expect 6 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
cp "$tmp/valid-origin" "$tmp/source-mirror/mirror-origin"
mv "$tmp/source-mirror/mirror-origin" "$tmp/origin-regular"
ln -s "$tmp/origin-regular" "$tmp/source-mirror/mirror-origin"
expect 6 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
rm "$tmp/source-mirror/mirror-origin"
mv "$tmp/origin-regular" "$tmp/source-mirror/mirror-origin"
before_current=$(grep -c '"GET /index\.' "$tmp/server.log" || true)
expect 3 "$bin" sync fixture --root "$tmp/source-root" --ca-file "$tmp/cert.pem"
grep -q "decision-required unsigned current source=$source_id index=$index" "$tmp/error"
expect 3 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-preview" --ca-file "$tmp/cert.pem"
grep -q "decision-required unsigned current source=$source_id index=$index" "$tmp/error"
test ! -e "$tmp/source-current-preview"
test "$(grep -c '"GET /index\.' "$tmp/server.log" || true)" -eq "$before_current"
expect 2 "$bin" sync fixture --root "$tmp/source-root" --sha256 "$index"
expect 6 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-untrusted" --accept-unsigned "$index"
test ! -e "$tmp/source-current-untrusted"
expect 2 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-invalid-answer" --accept-unsigned bad --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-current-invalid-answer"
expect 2 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-two-modes" --sha256 "$index" \
    --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-current-two-modes"
stale=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
expect 3 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-stale" --accept-unsigned "$stale" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-current-stale"
expect 0 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current" --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
grep -qx 'selection current-accepted-unsigned' "$tmp/source-current/mirror-origin"
cmp "$tmp/serve/current" "$tmp/source-current/current"
expect 0 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-current" \
    --output "$tmp/fetched" --root "$tmp/source-root"
cp "$tmp/serve/current" "$tmp/current.saved"
printf 'sha256 %s\n' "$stale" > "$tmp/serve/current"
expect 3 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-changed" --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-current-changed"
printf 'sha256 invalid\n' > "$tmp/serve/current"
expect 4 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-current-malformed" --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-current-malformed"
mv "$tmp/current.saved" "$tmp/serve/current"
expect 0 "$bin" repo solve "$tmp/source-mirror" https-second --json
grep -q '"count":2' "$tmp/result"
expect 6 "$bin" sync absent --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-absent" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-absent"
expect 6 "$bin" sync fixture --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-untrusted"
test ! -e "$tmp/source-untrusted/current"
expect 2 "$bin" sync fixture --root "$tmp/source-root" --sha256 bad \
    --output "$tmp/source-invalid" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-invalid"
printf '[source fixture]\ntype holy-http\nurl "%sredirect/"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
expect 3 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-redirect-preview" --ca-file "$tmp/cert.pem"
grep -q "index=$index" "$tmp/error"
expect 0 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-redirect" --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
grep -qx 'selection current-accepted-unsigned' "$tmp/source-redirect/mirror-origin"
printf '[source fixture]\ntype holy-http\nurl "%scredential/"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
expect 6 "$bin" sync fixture --root "$tmp/source-root" \
    --output "$tmp/source-credential" --accept-unsigned "$index" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-credential"
! grep -Eq 'user|pass' "$tmp/error"
printf '[source fixture]\ntype holy-http\nurl "%s"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
printf '[source renamed]\ntype holy-http\nurl "%s"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
expect 0 "$bin" sync renamed --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-renamed" --ca-file "$tmp/cert.pem"
grep -qx "source-id $source_id" "$tmp/source-renamed/mirror-origin"
expect 0 "$bin" fetch renamed:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
expect 0 "$bin" info renamed:https-fixture --root "$tmp/source-root"
grep -qx "source-id $source_id" "$tmp/result"
expect 0 "$bin" fetch renamed:https-fixture --output "$tmp/fetched" \
    --root "$tmp/source-root"
expect 6 "$bin" info fixture:https-fixture --root "$tmp/source-root"
expect 6 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
expect 6 "$bin" sync fixture --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-inactive" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-inactive"
printf '[source fixture]\ntype pacman\nrepo core "%s"\n' "$base" > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$tmp/source-root"
cp "$tmp/result" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$tmp/source-root"
expect 6 "$bin" fetch fixture:https-fixture --catalog "$tmp/source-mirror" \
    --output "$tmp/fetched" --root "$tmp/source-root"
expect 6 "$bin" sync fixture --root "$tmp/source-root" --sha256 "$index" \
    --output "$tmp/source-wrong-family" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/source-wrong-family"
expect 0 "$bin" repo search "$tmp/mirror" https-second
grep -q 'listed 1 packages' "$tmp/result"
expect 0 "$bin" repo solve "$tmp/mirror" https-second --json
grep -q '"count":2' "$tmp/result"
mkdir "$tmp/mirror-fetch"
expect 0 "$bin" repo fetch "$tmp/mirror" "$digest" --output "$tmp/mirror-fetch"
cmp "$tmp/mirror-fetch/$digest.holy" "$tmp/serve/native.holy"
expect 1 "$bin" repo mirror "$base" --sha256 "$index" --output "$tmp/mirror" --ca-file "$tmp/cert.pem"
cmp "$tmp/serve/current" "$tmp/mirror/current"
expect 6 "$bin" repo mirror "$base" --sha256 "$index" --output "$tmp/untrusted"
test ! -e "$tmp/untrusted/current"
expect 2 "$bin" repo mirror "https://user:pass@localhost:$port/" --sha256 "$index" --output "$tmp/credentials"
test ! -e "$tmp/credentials"
! grep -Eq 'user|pass' "$tmp/error"
expect 2 "$bin" repo mirror "${base}?query/" --sha256 "$index" --output "$tmp/query"
test ! -e "$tmp/query"
bad_index=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cp "$tmp/serve/index" "$tmp/serve/index.$bad_index"
expect 4 "$bin" repo mirror "$base" --sha256 "$bad_index" --output "$tmp/wrong-index" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/wrong-index/current"
mkdir "$tmp/serve/empty" "$tmp/serve/duplicate" "$tmp/serve/truncated"
printf 'format holy-index-prototype-2\n' > "$tmp/serve/empty/index"
cp "$tmp/serve/index" "$tmp/serve/duplicate/index"
tail -n 1 "$tmp/serve/index" >> "$tmp/serve/duplicate/index"
printf 'format holy-index-prototype-2\npackage "truncated\n' > "$tmp/serve/truncated/index"
for variant in empty duplicate truncated; do
    sum=$(sha256sum "$tmp/serve/$variant/index")
    sum=${sum%% *}
    cp "$tmp/serve/$variant/index" "$tmp/serve/$variant/index.$sum"
    wanted=4
    test "$variant" != empty || wanted=0
    expect "$wanted" "$bin" repo mirror "$base$variant/" --sha256 "$sum" \
        --output "$tmp/$variant" --ca-file "$tmp/cert.pem"
    if test "$wanted" -ne 0; then test ! -e "$tmp/$variant/current"; fi
done
expect 0 "$bin" repo list "$tmp/empty"
grep -qx 'listed 0 packages' "$tmp/result"
mv "$tmp/serve/space?#.holy" "$tmp/second.holy"
expect 6 "$bin" repo mirror "$base" --sha256 "$index" --output "$tmp/disappeared" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/disappeared/current"
mv "$tmp/second.holy" "$tmp/serve/space?#.holy"
cp "$tmp/serve/native.holy" "$tmp/original.holy"
printf changed > "$tmp/serve/native.holy"
expect 4 "$bin" repo mirror "$base" --sha256 "$index" --output "$tmp/changed-artifact" --ca-file "$tmp/cert.pem"
test ! -e "$tmp/changed-artifact/current"
cp "$tmp/original.holy" "$tmp/serve/native.holy"
mkdir "$tmp/serve/claims" "$tmp/serve/oversized"
cp "$tmp/serve/index" "$tmp/serve/claims/index"
second=$(sha256sum "$tmp/serve/space?#.holy" | cut -d ' ' -f 1)
printf 'claim %s package forged any any - fixture\n' "$second" >> "$tmp/serve/claims/index"
cp "$tmp/serve/native.holy" "$tmp/serve/space?#.holy" "$tmp/serve/claims/"
python3 - "$tmp/serve/oversized/index" <<'PY'
import sys
with open(sys.argv[1], 'wb') as stream:
    stream.write(b'x' * (17 * 1024 * 1024))
PY
for variant in claims oversized; do
    sum=$(sha256sum "$tmp/serve/$variant/index" | cut -d ' ' -f 1)
    cp "$tmp/serve/$variant/index" "$tmp/serve/$variant/index.$sum"
    wanted=4
    test "$variant" != oversized || wanted=6
    expect "$wanted" "$bin" repo mirror "$base$variant/" --sha256 "$sum" \
        --output "$tmp/$variant" --ca-file "$tmp/cert.pem"
    test ! -e "$tmp/$variant/current"
    test ! -s "$tmp/result"
done
printf 'HTTPS catalog mirror fixtures passed\n'
url="https://localhost:$port/native.holy"
"$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
    --ca-file "$tmp/cert.pem" > "$tmp/result"
grep -qx "$tmp/out/$digest.holy" "$tmp/result"
cmp "$tmp/serve/native.holy" "$tmp/out/$digest.holy"
"$bin" fetch "https://localhost:$port/redirect.holy" --sha256 "$digest" --output "$tmp/out" \
    --ca-file "$tmp/cert.pem" > "$tmp/result"
grep -qx "$tmp/out/$digest.holy" "$tmp/result"
before=$(grep -c '"GET /native.holy HTTP/' "$tmp/server.log")
if "$bin" fetch "https://localhost:$port/credential.holy" --sha256 "$digest" --output "$tmp/out" \
   --ca-file "$tmp/cert.pem" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 6; fi
test "$(grep -c '"GET /native.holy HTTP/' "$tmp/server.log")" -eq "$before"
test ! -s "$tmp/result"
if grep -Eq 'user|pass' "$tmp/error"; then exit 1; fi
"$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
    --ca-file "$tmp/cert.pem" > "$tmp/result"
bad=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if "$bin" fetch "$url" --sha256 "$bad" --output "$tmp/out" \
   --ca-file "$tmp/cert.pem" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/result"
test ! -e "$tmp/out/$bad.holy"
if "$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
   > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 6; fi
if "$bin" fetch "https://user:pass@localhost:$port/native.holy" \
   --sha256 "$digest" --output "$tmp/out" --ca-file "$tmp/cert.pem" \
   > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 2; fi
if grep -Eq 'user|pass' "$tmp/error"; then exit 1; fi
if "$bin" fetch "http://localhost:$port/native.holy" \
   --sha256 "$digest" --output "$tmp/out" \
   > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 2; fi
printf 'not an archive\n' > "$tmp/serve/bad.holy"
invalid=$(sha256sum "$tmp/serve/bad.holy")
invalid=${invalid%% *}
if "$bin" fetch "https://localhost:$port/bad.holy" --sha256 "$invalid" \
   --output "$tmp/out" --ca-file "$tmp/cert.pem" \
   > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 2; fi
test ! -e "$tmp/out/$invalid.holy"
printf 'corrupt\n' > "$tmp/out/$digest.holy"
if "$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
   --ca-file "$tmp/cert.pem" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 4; fi
grep -qx corrupt "$tmp/out/$digest.holy"
rm "$tmp/out/$digest.holy"
printf 'outside\n' > "$tmp/victim"
ln -s "$tmp/victim" "$tmp/out/$digest.holy"
if "$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
   --ca-file "$tmp/cert.pem" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 4; fi
grep -qx outside "$tmp/victim"
rm "$tmp/out/$digest.holy"
chmod 0770 "$tmp/out"
if "$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
   --ca-file "$tmp/cert.pem" > "$tmp/result" 2> "$tmp/error"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/out/$digest.holy"
chmod 0700 "$tmp/out"
printf 'https fixtures passed\n'
