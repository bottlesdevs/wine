#!/usr/bin/env bash
set -euo pipefail

test "$#" = 2
runner_dir="$(realpath "$1")"
work_dir="$2"
test -x "$runner_dir/bin/wine"
test -x "$runner_dir/bin/wineserver"
test ! -e "$work_dir"
mkdir -p "$work_dir"
work_dir="$(realpath "$work_dir")"
source_dir="$(cd "$(dirname "$0")" && pwd)"
export TMPDIR="$work_dir/tmp" TMP="$work_dir/tmp" TEMP="$work_dir/tmp"
mkdir -p "$TMPDIR"
export WINEPREFIX="$work_dir/prefix" WINEARCH=win64 WINEDEBUG=-all
export WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d'
if test -f "$runner_dir/share/fex-emu/Config.json"; then
    export FEX_APP_CONFIG="$runner_dir/share/fex-emu/Config.json"
    export FEX_APP_CONFIG_LOCATION="$runner_dir/share/fex-emu"
fi

cleanup()
{
    status=$?
    "$runner_dir/bin/wineserver" -k >"$work_dir/server-cleanup.log" 2>&1 || true
    if "$runner_dir/bin/wineserver" -w >>"$work_dir/server-cleanup.log" 2>&1; then
        rm -rf -- "$work_dir/prefix"
    else
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$WINEPREFIX"
"$runner_dir/bin/wineserver" -p
"$runner_dir/bin/wine" wineboot -u
for bits in 64 32; do
    compiler=x86_64-w64-mingw32-gcc
    test "$bits" = 64 || compiler=i686-w64-mingw32-gcc
    exe="$work_dir/imports$bits.exe"
    "$compiler" "$source_dir/soda-typelib-imports.c" -municode -O2 -Wall -Wextra -Werror \
        -loleaut32 -lole32 -luuid -o "$exe"
    cases=0
    for base_kind in 32 64; do
        for alias_kind in 32 64; do
            for registration in one both; do
                name="$bits-$base_kind-$alias_kind-$registration"
                directory="$work_dir/$name"
                mkdir "$directory"
                make_mode=make
                probe_mode=probe
                expected=42
                if test "$registration" = both; then
                    make_mode=make-both
                    probe_mode=probe-both
                    test "$base_kind" = "$bits" || expected=84
                fi
                "$runner_dir/bin/wine" "$exe" "$make_mode" "$base_kind" "$alias_kind" "Z:$directory" \
                    | tr -d '\r' | tee "$directory/make.log"
                test ! -e "$directory/base-original.tlb"
                "$runner_dir/bin/wine" "$exe" "$probe_mode" "Z:$directory/importing.tlb" \
                    | tr -d '\r' | tee "$directory/probe.log"
                grep -Fx "RESOLVED_CONSTANT value=$expected" "$directory/probe.log"
                grep -Fx "LOOKUP hr=00000000 RESULT=00000000 POINTER_BITS=$bits" "$directory/probe.log"
                "$runner_dir/bin/wine" "$exe" cleanup \
                    | tr -d '\r' | tee "$directory/cleanup.log"
                cases=$((cases + 1))
            done
        done
    done
    test "$cases" = 8
    printf 'TYPELIB_IMPORT_RESULT bits=%s cases=%s failures=0\n' "$bits" "$cases"
done
