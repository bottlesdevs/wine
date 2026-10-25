#!/usr/bin/env bash
set -euo pipefail
work=${1:?usage: soda-compiler-cache-smoke.sh WORK COMPILER [FLAGS...]}
compiler=${2:?usage: soda-compiler-cache-smoke.sh WORK COMPILER [FLAGS...]}
shift 2
flags=("$@")
prefix=(ccache)
if [[ "${CCACHE_SMOKE_DIRECT:-0}" == 1 ]]; then prefix=(); fi
mkdir -p "$work"
cat > "$work/fixture.c" <<'SOURCE'
#include "fixture.h"
#ifndef EXTRA
#define EXTRA 0
#endif
int cache_fixture(void) { return FIXTURE_VALUE + EXTRA; }
SOURCE
printf '#define FIXTURE_VALUE 7\n' > "$work/fixture.h"
compile() {
    "${prefix[@]}" "$compiler" "${flags[@]}" -O2 -g "$@" -c "$work/fixture.c" -o "$work/fixture.o"
}
hits() {
    ccache --print-stats | awk '$1 == "direct_cache_hit" || $1 == "preprocessed_cache_hit" { sum += $2 } END { print sum + 0 }'
}
CCACHE_DISABLE=1 compile
cp "$work/fixture.o" "$work/direct.o"
compile
cmp "$work/direct.o" "$work/fixture.o"
before=$(hits)
compile
after=$(hits)
test "$after" -gt "$before"
cmp "$work/direct.o" "$work/fixture.o"
printf '#define FIXTURE_VALUE 13\n' > "$work/fixture.h"
CCACHE_DISABLE=1 compile
cp "$work/fixture.o" "$work/header.o"
compile
cmp "$work/header.o" "$work/fixture.o"
if cmp -s "$work/direct.o" "$work/fixture.o"; then exit 1; fi
CCACHE_DISABLE=1 compile -DEXTRA=5
cp "$work/fixture.o" "$work/flags.o"
compile -DEXTRA=5
cmp "$work/flags.o" "$work/fixture.o"
if cmp -s "$work/header.o" "$work/fixture.o"; then exit 1; fi
printf 'CCACHE_SMOKE compiler=%s hits_before=%s hits_after=%s header_and_flags=ok\n' "$compiler" "$before" "$after"
ccache --show-stats
