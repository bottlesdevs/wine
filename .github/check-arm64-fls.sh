#!/usr/bin/env bash
set -euo pipefail

test "$#" = 3
baseline="$(realpath "$1")"
candidate="$(realpath "$2")"
work="$(realpath "$3")"
source_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$work/results" "$work/programs" "$work/prefixes" "$work/scratch"
export TMPDIR="$work/scratch" TMP="$work/scratch" TEMP="$work/scratch"
export WINEARCH=win64 WINEDEBUG=-all LIBGL_ALWAYS_SOFTWARE=1
export WINEDLLOVERRIDES='mscoree,mshtml=;winemenubuilder.exe=d'

for bits in 64 32; do
    compiler=x86_64-w64-mingw32-g++
    test "$bits" = 64 || compiler=i686-w64-mingw32-g++
    for probe in dashes scaled-dashes; do
        source="$source_dir/soda-d2d-$probe.cpp"
        test "$probe" != dashes || source="$source_dir/soda-d2d-dashes-smoke.cpp"
        "$compiler" "$source" -O2 -Wall -Wextra -Werror \
            -static-libgcc -static-libstdc++ -ld2d1 -lwindowscodecs -lole32 -luuid \
            -o "$work/programs/$probe$bits.exe"
    done
done

for label in baseline candidate; do
    runner="$baseline"
    test "$label" = baseline || runner="$candidate"
    export FEX_APP_CONFIG="$runner/share/fex-emu/Config.json"
    export FEX_APP_CONFIG_LOCATION="$runner/share/fex-emu"
    set +e
    bash "$source_dir/check-fls.sh" "$runner" "$work/fls-$label" \
        >"$work/results/fls-$label.log" 2>&1
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/results/fls-$label.status"
    mkdir "$work/results/fls-$label"
    for path in "$work/fls-$label"/*.log "$work/fls-$label"/*.stderr \
            "$work/fls-$label"/*.json "$work/fls-$label"/*.sha256; do
        test ! -f "$path" || cp "$path" "$work/results/fls-$label/"
    done
done

finish_server()
{
    if test -n "${server_pid:-}"; then
        "$runner/bin/wineserver" -k >>"$directory/server-cleanup.log" 2>&1 || true
        set +e
        wait "$server_pid"
        status=$?
        set -e
        printf '%s\n' "$status" >"$directory/server.status"
        server_pid=
    fi
}
trap finish_server EXIT
printf 'round\tmode\trunner\tbits\tprobe\tstatus\tserver_alive\n' >"$work/results/drawing.tsv"
for round in 1 2; do
    for mode in default persistent; do
        for label in baseline candidate; do
            runner="$baseline"
            test "$label" = baseline || runner="$candidate"
            export FEX_APP_CONFIG="$runner/share/fex-emu/Config.json"
            export FEX_APP_CONFIG_LOCATION="$runner/share/fex-emu"
            export WINEPREFIX="$work/prefixes/$round-$mode-$label"
            directory="$work/results/$round-$mode-$label"
            mkdir -p "$WINEPREFIX" "$directory"
            arguments=(-f)
            test "$mode" = default || arguments+=(-p)
            "$runner/bin/wineserver" "${arguments[@]}" >"$directory/server.log" 2>&1 &
            server_pid=$!
            set +e
            timeout 90 "$runner/bin/wine" wineboot -u >"$directory/wineboot.log" 2>&1
            status=$?
            set -e
            printf '%s\n' "$status" >"$directory/wineboot.status"
            if test "$status" = 0; then
                for bits in 64 32; do
                    for probe in dashes scaled-dashes; do
                        set +e
                        timeout 90 "$runner/bin/wine" "$work/programs/$probe$bits.exe" \
                            >"$directory/$probe$bits.log" 2>"$directory/$probe$bits.stderr"
                        status=$?
                        set -e
                        alive=0
                        if kill -0 "$server_pid" 2>/dev/null; then alive=1; fi
                        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                            "$round" "$mode" "$label" "$bits" "$probe" "$status" "$alive" \
                            >>"$work/results/drawing.tsv"
                    done
                done
            fi
            finish_server
        done
    done
done

python3 - "$work/results" "$source_dir" <<'PY'
import csv, json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
expected = json.loads((Path(sys.argv[2]) / 'soda-fls-expected.json').read_text())['cases']
baseline = json.loads((root / 'fls-baseline/comparison.json').read_text())
candidate = json.loads((root / 'fls-candidate/comparison.json').read_text())
with (root / 'drawing.tsv').open() as file:
    drawing = list(csv.DictReader(file, delimiter='\t'))
result = {'baseline': baseline, 'candidate': candidate, 'drawing': drawing}
(root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
assert len(baseline) == len(candidate) == 2
assert all(len(item['actual']) == 10 and not item['matched'] for item in baseline)
for item in baseline:
    changed = [native['case'] for native, actual in zip(expected, item['actual']) if native != actual]
    assert changed == ['free', 'free-reset', 'free-reset-four', 'free-reset-sixteen', 'free-fibers', 'free-fibers-reset']
assert all(len(item['actual']) == 10 and item['matched'] for item in candidate)
assert (root / 'fls-baseline.status').read_text().strip() == '1'
assert (root / 'fls-candidate.status').read_text().strip() == '0'
assert len(drawing) == 32 and all(item['status'] == '0' for item in drawing)
for item in drawing:
    directory = root / f"{item['round']}-{item['mode']}-{item['runner']}"
    output = (directory / f"{item['probe']}{item['bits']}.log").read_text()
    marker = 'DASH_RESULT' if item['probe'] == 'dashes' else 'SCALED_DASH_RESULT'
    assert re.search(rf'^{marker} checks=[1-9][0-9]* failures=0$', output, re.M)
print('ARM_FLS_RESULT architectures=2 cases=10 baseline_differs=1 candidate_matches=1')
print('ARM_DRAWING_RESULT processes=32 failures=0')
PY
