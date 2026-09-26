#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/root" <<'EOF'
[general]
arch x86_64
include "child"
[source arch]
type pacman
repo core "https://example.org/$repo/$arch" # no shell expansion
repo extra "https://example.org/a b"
[rule rizin-zlib]
consumer aur:rizin
require "elf:x86_64:glibc:libz.so.1"
provider void:zlib
EOF
cat > "$tmp/child" <<'EOF'
[general]
scripts ask
[resolver]
prefer installed
prefer same-source
EOF
"$bin" config check "$tmp/root" > "$tmp/out"
grep -q '10 entries' "$tmp/out"
cat > "$tmp/duplicate" <<'EOF'
[general]
arch x86
arch x86_64
EOF
if "$bin" config check "$tmp/duplicate" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'first at .*:2' "$tmp/err"
cat > "$tmp/cycle" <<'EOF'
include "cycle"
EOF
if "$bin" config check "$tmp/cycle" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'include cycle' "$tmp/err"
cat > "$tmp/bad" <<'EOF'
[general]
arch "unterminated
EOF
if "$bin" config check "$tmp/bad" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unterminated quote' "$tmp/err"
printf '[general]\narch x86\\x00\n' > "$tmp/nul"
if "$bin" config check "$tmp/nul" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid escape or NUL' "$tmp/err"
printf '[source local]\ntype pacman\n' > "$tmp/reserved"
if "$bin" config check "$tmp/reserved" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid section' "$tmp/err"
printf '[source arch]\nrepo main\n' > "$tmp/arity"
if "$bin" config check "$tmp/arity" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'expects 2 argument' "$tmp/err"
printf '[general]\nscripts unsafe\n' > "$tmp/value"
if "$bin" config check "$tmp/value" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid scripts value' "$tmp/err"
printf '[general]\narch \377\n' > "$tmp/encoding"
if "$bin" config check "$tmp/encoding" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid UTF-8' "$tmp/err"
cat > "$tmp/incomplete-source" <<'EOF'
[source extra]
type holy-http
EOF
if "$bin" config check "$tmp/incomplete-source" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'requires type and url or repo' "$tmp/err"
cat > "$tmp/incomplete-rule" <<'EOF'
[rule broken]
consumer arch:hello
EOF
if "$bin" config check "$tmp/incomplete-rule" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'requires consumer, require and provider' "$tmp/err"
cat > "$tmp/repo-duplicate" <<'EOF'
[source arch]
type pacman
repo main "https://mirror.example/a"
repo main "https://mirror.example/b"
EOF
if "$bin" config check "$tmp/repo-duplicate" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'duplicate repo name' "$tmp/err"
cat > "$tmp/split-source" <<'EOF'
[source native]
type holy-http
include "split-source-child"
EOF
cat > "$tmp/split-source-child" <<'EOF'
[source native]
url "https://mirror.example/holy"
EOF
"$bin" config check "$tmp/split-source" > "$tmp/out"
grep -q '2 entries' "$tmp/out"
printf 'config fixtures passed\n'
