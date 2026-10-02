#!/bin/sh
# writes the index page and its plain-text twin for a published native repository. the
# page is derived from the directory that was actually published, so it cannot claim a
# package the index does not carry or hide one it does. a static file server has no
# directory listing of its own worth showing, and an index makes the listing unnecessary.
#
# usage: packages-page.sh MIRROR_DIRECTORY OUTPUT_DIRECTORY
set -eu

mirror=${1:?usage: packages-page.sh MIRROR_DIRECTORY OUTPUT_DIRECTORY}
out=${2:?usage: packages-page.sh MIRROR_DIRECTORY OUTPUT_DIRECTORY}

for name in index current; do
    test -f "$mirror/$name" || { printf 'packages-page: %s/%s is not a file\n' "$mirror" "$name" >&2; exit 1; }
done

generation=$(sed -n 's/^sha256 //p' "$mirror/current")
test "${#generation}" = 64 || {
    printf 'packages-page: current names a %s character digest, not 64\n' "${#generation}" >&2
    exit 1; }

# the digest a client pins, shown in both forms so a reader does not have to guess which
# one belongs in a config
short=$(printf '%s' "$generation" | cut -c1-12)
signature=$mirror/signature.$generation
if test -f "$signature"; then
    signature_size=$(wc -c < "$signature" | tr -d ' ')
    signature_state="signed, ${signature_size} bytes"
else
    signature_state="unsigned"
fi
public_key=$mirror/holy-packages.pub
if test -f "$public_key" && command -v openssl >/dev/null 2>&1; then
    # the raw 32 bytes, which is the form a configuration carries. openssl prints them
    # as an indented colon-separated block under a pub: heading, possibly wrapped
    key_hex=$(openssl pkey -pubin -in "$public_key" -text -noout 2>/dev/null |
              sed -n 's/^[[:space:]]*\([0-9a-f][0-9a-f:]\{2,\}\)[[:space:]]*$/\1/p' |
              tr -d ':\n' | tr 'A-F' 'a-f')
    if test "${#key_hex}" = 64; then
        key_line="public-key-ed25519 ${key_hex}"
    else
        key_line="public key published, its raw bytes were not readable here"
    fi
else
    key_line="no public key published"
fi

# the package records of the index become one pipe-separated line each. the index is a
# text document with a fixed record order, so a substitution is enough and no field can
# be read out of step with its neighbours
records=$(sed -n 's/^package "\([^"]*\)" "\([^"]*\)" "\([^"]*\)" "\([^"]*\)" "\([^"]*\)" "\([^"]*\)" "\([^"]*\)" \([0-9a-f]*\) \([0-9]*\) .*/\1|\2|\3|\4|\5|\6|\7|\8|\9/p' \
           "$mirror/index")
test -n "$records" || { printf 'packages-page: the index carries no package\n' >&2; exit 1; }

list=''
total=0
count=0
# the page shows the slot, not the os, and the size in kilobytes, so the record carries
# exactly the fields both output forms read
for record in $records; do
    size=$(printf '%s' "$record" | cut -d'|' -f9)
    total=$(( total + size ))
    count=$(( count + 1 ))
    list="$list$(printf '%s' "$record" | cut -d'|' -f1,2,3,5,6,7)|$(( (size + 1023) / 1024 ))
"
done

test "$count" -gt 0 || { printf 'packages-page: the index carries no package\n' >&2; exit 1; }

{
    cat <<EOF
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />

    <link rel="icon" href="/favicon.ico" sizes="any" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
    <link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />

    <title>packages.holypkg.eu</title>

    <style>
        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
            background: #000;
            color: #8d8d8d;
        }

        body {
            min-height: 100dvh;
            display: flex;
            align-items: center;
            justify-content: center;

            font-family: "Courier New", Courier, monospace;
            font-size: 14px;
            line-height: 1.5;
        }

        main {
            width: 100%;
            max-width: 860px;
            padding: clamp(42px, 10vh, 100px) clamp(14px, 4vw, 28px) 42px;

            text-align: center;
        }

        .logo {
            display: inline-block;

            margin: 0 0 24px;
            padding: 0;

            color: #d4d4d4;

            font-size: clamp(14px, 3vw, 20px);
            font-weight: 400;
            line-height: 1;
            text-align: left;
            white-space: pre;
        }

        h1 {
            margin: 0;

            color: #d0d0d0;

            font-size: 18px;
            font-weight: 400;
        }

        .description {
            max-width: 470px;
            margin: 12px auto 0;

            color: #686868;
            font-size: 12px;
        }

        .terminal {
            display: inline-block;

            max-width: 100%;
            overflow-x: auto;

            margin: 0 auto 30px;
            padding: 5px 0 5px 14px;

            border-left: 1px solid #292929;

            color: #aaa;

            text-align: left;
            white-space: pre;

            scrollbar-width: none;
        }

        .terminal::-webkit-scrollbar {
            display: none;
        }

        .prompt {
            color: #4d4d4d;
        }

        .packages {
            margin: 0 auto 34px;
            padding: 0;

            border-collapse: collapse;
            list-style: none;
            text-align: left;
        }

        .packages li {
            padding: 3px 0;
            border-left: 1px solid #1e1e1e;
        }

        .packages a {
            color: #8d8d8d;
        }

        .packages a:hover {
            color: #fff;
        }

        .packages .slot {
            color: #b0b0b0;
        }

        .packages .size {
            color: #454545;
            font-size: 12px;
        }

        a {
            color: #a0a0a0;
            text-decoration: none;
        }

        a:hover {
            color: #fff;
        }

        .links {
            font-size: 12px;
            line-height: 1.9;
        }

        footer {
            margin-top: 40px;

            color: #3b3b3b;
            font-size: 11px;
        }

        footer a {
            color: inherit;
        }

        footer a:hover {
            color: #888;
        }

        ::selection {
            background: #ccc;
            color: #000;
        }

        @media (max-width: 480px) {
            main {
                padding-top: 8vh;
            }

            .packages {
                font-size: 12px;
            }
        }
    </style>
</head>

<body>
    <main>
        <pre class="logo"> _       _
| |_ ___| |_ _
|   | . | | | |
|_|_|___|_|_  |
          |___|</pre>

        <h1>holy packages</h1>

        <p class="description">
            native .holy repository for the holy base, one index generation
            signed with ed25519. add a source to use it, and pin the generation
            you reviewed.
        </p>

        <div class="terminal"><span class="prompt">$</span> holypkg add packages:musl --arch x86_64
<span class="prompt">$</span> holypkg sync packages --sha256 $generation</div>

        <ul class="packages">
EOF
    printf '%s' "$list" | while IFS='|' read -r name version release arch libc file kb; do
        test -n "$name" || continue
        cat <<EOF
            <li><a href="/$file">$name</a> <span class="slot">$arch $libc</span> <span class="size">$version-$release ${kb}kB</span></li>
EOF
    done
    cat <<EOF
        </ul>

        <div class="terminal"><span class="prompt">$</span> cat current
sha256 $generation
<span class="prompt">$</span> cat index.$short
$count packages, signature $signature_state
<span class="prompt">$</span> cat index | head -1
format holy-index-prototype-8</div>

        <div class="links">
            <a href="/index">index</a><br />
            <a href="/current">current</a><br />
            <a href="/index.$generation">index.$short</a><br />
            <a href="/signature.$generation">signature</a><br />
            <a href="/holy-packages.pub">public key</a>
        </div>

        <footer>
            generation <a href="/index.$generation">$short</a> &middot;
            <a href="mailto:contact@holypkg.eu">contact@holypkg.eu</a>
        </footer>
    </main>
</body>
</html>
EOF
} > "$out/index.html"

{
    cat <<EOF
 _       _
| |_ ___| |_ _
|   | . | | | |
|_|_|___|_|_  |
          |___|

packages.holypkg.eu :~\$ cat status

holy packages, the reference source of the holy base.
$count packages in one signed index generation, $(( total / 1024 ))kB total.
EOF
    printf '%s' "$list" | while IFS='|' read -r name version release arch libc file kb; do
        test -n "$name" || continue
        printf '%-22s %-8s %-8s %-10s %s\n' "$name" "$arch" "$libc" "${version}-${release}" "$file"
    done
    cat <<EOF

${key_line}
index-sha256 $generation
signature   $signature_state

add a source to a configuration, then pin the generation you reviewed:

  [source packages]
  type holy-http
  url "https://packages.holypkg.eu/"

  holypkg sync packages --sha256 $generation
EOF
} > "$out/packages.txt"

printf 'packages-page %s generation %s packages %d\n' "$out" "$short" "$count"
