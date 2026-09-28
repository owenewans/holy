#!/bin/sh
set -eu
test "$#" -eq 2 || exit 2
source=$(realpath "$1") || exit 6
destination=$2
test -d "$source/inputs" && test -d "$source/packages" && \
    test -f "$source/build.record" && test -f "$source/plan" && \
    test -f "$source/install.plan" && test -f "$source/input-lock.sha256" && \
    test -f "$source/boot-plan" && test -f "$source/host-tools.jsonl" || {
    echo 'holygetiso: image input set is incomplete' >&2
    exit 6
}
test ! -e "$destination" && test ! -L "$destination" || {
    echo 'holygetiso: export directory exists' >&2
    exit 2
}
mkdir -m 0700 -- "$destination"
export_root=$(realpath "$destination")
cleanup() {
    status=$?
    if test "$status" -ne 0; then rm -rf -- "$export_root"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
case "$export_root" in
    "$source"/*)
        echo 'holygetiso: export must be outside image output' >&2
        exit 2 ;;
esac
expected_lock=$(sed -n 's/^input-lock-sha256 \([0-9a-f]*\)$/\1/p' "$source/build.record")
test "${#expected_lock}" -eq 64 || exit 6
actual_lock=$(sha256sum "$source/input-lock.sha256")
test "${actual_lock%% *}" = "$expected_lock" || {
    echo 'holygetiso: input lock changed' >&2
    exit 6
}
expected_tools=$(sed -n 's/^host-tools-sha256 \([0-9a-f]*\)$/\1/p' "$source/build.record")
actual_tools=$(sha256sum "$source/host-tools.jsonl")
test "${#expected_tools}" -eq 64 && test "${actual_tools%% *}" = "$expected_tools" || {
    echo 'holygetiso: host tool record changed' >&2
    exit 6
}
(cd "$source" && sha256sum -c input-lock.sha256 > /dev/null) || {
    echo 'holygetiso: build input changed' >&2
    exit 6
}
expected_plan=$(cat "$source/boot-plan")
actual_plan=$(sha256sum "$source/plan")
test "${#expected_plan}" -eq 64 && test "${actual_plan%% *}" = "$expected_plan" || {
    echo 'holygetiso: build plan changed' >&2
    exit 6
}
expected_install=$(sed -n 's/^install-plan-file-sha256 \([0-9a-f]*\)$/\1/p' "$source/build.record")
actual_install=$(sha256sum "$source/install.plan")
test "${#expected_install}" -eq 64 && test "${actual_install%% *}" = "$expected_install" || {
    echo 'holygetiso: install plan changed' >&2
    exit 6
}
if test -f "$source/source.plan"; then
    expected_source=$(sed -n 's/^source-plan \([0-9a-f]*\)$/\1/p' "$source/build.record")
    actual_source=$(sha256sum "$source/source.plan")
    test "${#expected_source}" -eq 64 && test "${actual_source%% *}" = "$expected_source" || {
        echo 'holygetiso: source plan changed' >&2
        exit 6
    }
fi
for path in inputs packages mirrors; do
    test -d "$source/$path" || {
        test "$path" = mirrors || exit 6
        continue
    }
    test ! -L "$source/$path" || exit 6
    test -z "$(find "$source/$path" -type l -print -quit)" || {
        echo "holygetiso: symlink in $path" >&2
        exit 6
    }
    cp -R -- "$source/$path" "$export_root/$path"
done
for path in build.record plan install.plan boot-plan input-lock.sha256 host-tools.jsonl; do
    test -f "$source/$path" && test ! -L "$source/$path" || exit 6
    cp -- "$source/$path" "$export_root/$path"
done
if test -f "$source/source.plan"; then
    test ! -L "$source/source.plan" || exit 6
    cp -- "$source/source.plan" "$export_root/source.plan"
fi
(
    cd "$export_root"
    set -- inputs packages
    if test -d mirrors; then set -- "$@" mirrors; fi
    find "$@" -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum build.record plan install.plan boot-plan input-lock.sha256 host-tools.jsonl >> SHA256SUMS
    if test -f source.plan; then sha256sum source.plan >> SHA256SUMS; fi
    sha256sum -c SHA256SUMS > /dev/null
)
printf '%s\n' "$export_root"
