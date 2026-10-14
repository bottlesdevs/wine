#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:?usage: build-native.sh DESTINATION YARA_SOURCE WORK}
source=${2:?usage: build-native.sh DESTINATION YARA_SOURCE WORK}
work=${3:?usage: build-native.sh DESTINATION YARA_SOURCE WORK}
for directory in "$destination" "$work"; do
    if test -e "$directory"; then
        printf 'Build destination already exists: %s\n' "$directory" >&2
        exit 1
    fi
done
python3 - "$root" "$destination" "$work" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
destination, work = (Path(value).resolve() for value in sys.argv[2:])
if destination == work or destination in work.parents:
    raise SystemExit('Build work must be outside the package destination')
sources = json.loads((root / 'sources.json').read_text())
for name, expected in sources['assets'].items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
        raise SystemExit('Source checksum mismatch: ' + name)
PYTHON
mkdir -p "$work/t"
work=$(CDPATH= cd -- "$work" && pwd)
export TMPDIR="$work/t" TMP="$work/t" TEMP="$work/t"
sh "$root/prepare-yara.sh" "$source" "$work/yara"
sh "$root/build-analysis.sh" "$work/analysis"
sh "$root/build-debugger.sh" "$work/debugger"
mkdir -p "$destination"
destination=$(CDPATH= cd -- "$destination" && pwd)
cp -a "$work/debugger/." "$destination/"
cp -a "$work/analysis/." "$destination/"
cd "$root"
g++ -std=c++17 -O2 -g -Wall -Wextra -Werror -static \
    -ffile-prefix-map="$root"=/usr/src/soda/eagle \
    -ffile-prefix-map="$work"=/usr/src/soda/eagle-build \
    -I"$work/yara/source/libyara/include" "$root/native/yara.cpp" \
    "$work/yara/build/.libs/libyara.a" -lm -pthread \
    -o "$destination/lib/eagle/native/eagle-yara"
mkdir -p "$destination/lib/eagle/engine"
cp "$root/engine/eagle.yar" "$root/engine/eagle-intel.sqlite" \
    "$root/engine/eagle-intel-data-license.txt" "$destination/lib/eagle/engine/"
cp "$root/native/vendor/YARA-COPYING" "$destination/share/eagle/licenses/"
cp "$root/sources.json" "$destination/share/eagle/"
EAGLE_PACKAGE="$destination" python3 -S "$root/tests/test_native_package.py"
