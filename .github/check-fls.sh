#!/usr/bin/env bash
set -euo pipefail

test "$#" = 2
runner_dir="$(realpath "$1")"
work_dir="$2"
test -x "$runner_dir/bin/wine"
test -x "$runner_dir/bin/wineserver"
test ! -e "$work_dir"
mkdir -p "$work_dir/tmp"
work_dir="$(realpath "$work_dir")"
source_dir="$(cd "$(dirname "$0")" && pwd)"
export TMPDIR="$work_dir/tmp" TMP="$work_dir/tmp" TEMP="$work_dir/tmp"
export WINEPREFIX="$work_dir/prefix" WINEARCH=win64 WINEDEBUG=-all
export WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d'
if test -f "$runner_dir/share/fex-emu/Config.json"; then
    export FEX_APP_CONFIG="$runner_dir/share/fex-emu/Config.json"
    export FEX_APP_CONFIG_LOCATION="$runner_dir/share/fex-emu"
fi
trap '"$runner_dir/bin/wineserver" -k; "$runner_dir/bin/wineserver" -w' EXIT

"$runner_dir/bin/wine" wineboot -u >"$work_dir/wineboot.log" 2>&1
sha256sum "$source_dir/soda-fls-reference.c" >"$work_dir/source.sha256"
for bits in 64 32; do
    compiler=x86_64-w64-mingw32-gcc
    test "$bits" = 64 || compiler=i686-w64-mingw32-gcc
    "$compiler" -std=c11 -O2 -g -Wall -Wextra -Werror -static \
        "$source_dir/soda-fls-reference.c" -o "$work_dir/fls$bits.exe"
    sha256sum "$work_dir/fls$bits.exe" >"$work_dir/fls$bits.sha256"
    timeout 90 "$runner_dir/bin/wine" "$work_dir/fls$bits.exe" \
        >"$work_dir/fls$bits.log" 2>"$work_dir/fls$bits.stderr"
done

python3 - "$source_dir" "$work_dir" <<'PY'
import hashlib, json, sys
from pathlib import Path
source, work = map(Path, sys.argv[1:])
expected = json.loads((source / 'soda-fls-expected.json').read_text())
assert hashlib.sha256((source / 'soda-fls-reference.c').read_bytes()).hexdigest() == expected['source_sha256']
results = []
for bits in (32, 64):
    actual = [json.loads(line) for line in (work / f'fls{bits}.log').read_text().splitlines()]
    results.append({'bits': bits, 'matched': actual == expected['cases'], 'actual': actual})
(work / 'comparison.json').write_text(json.dumps(results, indent=2) + '\n')
assert all(result['matched'] for result in results), 'FLS callback results differ from Windows'
print(f"FLS_RESULT architectures=2 cases={len(expected['cases'])} failures=0")
PY
