#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive=${1:?usage: package-eagle-overlay.sh BASELINE_ARCHIVE WINE_BUILD WORK}
build=$(CDPATH= cd -- "${2:?Wine build directory required}" && pwd)
work=${3:?New work directory required}
test ! -e "$work"
printf '%s  %s\n' 197df341e4011f6cc60d4c6c8f1d281cd6622e323d3fdb94951295f3c24c9430 "$archive" | sha256sum --check -
mkdir -p "$work/t"
work=$(CDPATH= cd -- "$work" && pwd)
export TMPDIR="$work/t" TMP="$work/t" TEMP="$work/t"
component=soda-11.0-26-experimental-x86_64
tar -C "$work" -xJf "$archive"
mv "$work/soda-11.0-25-experimental-x86_64" "$work/$component"
for architecture in i386 x86_64; do
    for module in combase dwrite kernelbase; do
        source="$build/dlls/$module/$architecture-windows/$module.dll"
        test -f "$source"
        grep -aFq EAGLE/1 "$source"
        cp "$source" "$work/$component/lib/wine/$architecture-windows/$module.dll"
    done
done
sh "$root/.github/build-eagle.sh" "$work/$component" "$work/acceptance"
python3 - "$work/$component" <<'PYTHON'
from pathlib import Path
import sys
runner = Path(sys.argv[1])
for path in (runner / 'lib/eagle').rglob('*.pyc'):
    path.unlink()
for path in (runner / 'lib/eagle').rglob('__pycache__'):
    path.rmdir()
PYTHON
tar -C "$work" -cJf "$work/$component.tar.xz" "$component"
sha256sum "$work/$component.tar.xz"
