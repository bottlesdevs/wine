#!/usr/bin/env bash
set -euo pipefail

test "$#" = 2
[[ "$WINE_MONO_VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]]
[[ "$WINE_MONO_SHA256" =~ ^[0-9a-f]{64}$ ]]
cache_dir="$1"
work_dir="$2"
mono_file="wine-mono-$WINE_MONO_VERSION-x86.msi"
archive="$cache_dir/$mono_file"
mkdir -p "$cache_dir" "$work_dir/tmp"
export TMPDIR="$work_dir/tmp" TMP="$work_dir/tmp" TEMP="$work_dir/tmp"

if test -f "$archive"; then
    printf '%s  %s\n' "$WINE_MONO_SHA256" "$archive" | sha256sum --check -
    exit 0
fi

download="$work_dir/$mono_file"
trap 'rm -f -- "$download"' EXIT
mono_url="https://github.com/wine-mono/wine-mono/releases/download/wine-mono-$WINE_MONO_VERSION/$mono_file"
if ! curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 --output "$download" "$mono_url"; then
    asset_id="$(gh api "repos/wine-mono/wine-mono/releases/tags/wine-mono-$WINE_MONO_VERSION" \
        --jq ".assets[] | select(.name == \"$mono_file\") | .id")"
    [[ "$asset_id" =~ ^[0-9]+$ ]]
    gh api "repos/wine-mono/wine-mono/releases/assets/$asset_id" \
        --header 'Accept: application/octet-stream' > "$download"
fi
printf '%s  %s\n' "$WINE_MONO_SHA256" "$download" | sha256sum --check -
mv -- "$download" "$archive"
