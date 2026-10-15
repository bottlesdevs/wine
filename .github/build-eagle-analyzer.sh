#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner=$(CDPATH= cd -- "${1:?usage: build-eagle-analyzer.sh RUNNER WORK}" && pwd)
work=${2:?usage: build-eagle-analyzer.sh RUNNER WORK}
test -x "$runner/bin/wine"
sh "$root/eagle/build-native.sh" "$work/package" - "$work/native" analyzer-only
python3 -S "$root/eagle/tests/test_native_build.py"
cp -a "$work/package/." "$runner/"
EAGLE_PACKAGE="$runner" python3 -S "$root/eagle/tests/test_analyzer_package.py"
