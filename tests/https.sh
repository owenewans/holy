#!/bin/sh
set -eu

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
server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
' "$tmp/serve" "$tmp/cert.pem" "$tmp/key.pem" > "$tmp/port" 2> "$tmp/server.log" &
server=$!
read -r port < "$tmp/port"
test -n "$port"
url="https://localhost:$port/native.holy"
"$bin" fetch "$url" --sha256 "$digest" --output "$tmp/out" \
    --ca-file "$tmp/cert.pem" > "$tmp/result"
grep -qx "$tmp/out/$digest.holy" "$tmp/result"
cmp "$tmp/serve/native.holy" "$tmp/out/$digest.holy"
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
