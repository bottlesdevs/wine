#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 - "$root" <<'PYTHON'
import ast
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = [root / name for name in ('cli.py', 'session.py', 'protocol.py', 'symbols.py', 'dap.py', 'errors.py', 'waits.py', 'tracing.py')]
files.extend((root / 'engine').glob('*.py'))
for path in files:
    ast.parse(path.read_text(), filename=str(path))
PYTHON
destination=${1:?usage: build.sh DESTINATION}
case "$destination" in
    /*) ;;
    *) destination="$PWD/$destination" ;;
esac
if test -e "$destination"; then
    printf 'Build destination already exists: %s\n' "$destination" >&2
    exit 1
fi
mkdir -p "$destination/lib/eagle/native" "$destination/bin"
cd "$root"
host_build()
{
    g++ -std=c++17 -O2 -g -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda/eagle "$@"
}
host_build "$root/native/pe.cpp" -o "$destination/lib/eagle/native/eagle-pe"
host_build "$root/native/elf.cpp" -o "$destination/lib/eagle/native/eagle-elf"
host_build $(pkg-config --cflags json-c glib-2.0) \
    "$root/native/analysis.cpp" $(pkg-config --libs --static json-c glib-2.0) -o "$destination/lib/eagle/native/eagle-analysis"
host_build $(pkg-config --cflags glib-2.0 json-c sqlite3) \
    "$root/native/intel.cpp" $(pkg-config --libs --static glib-2.0 json-c sqlite3) -o "$destination/lib/eagle/native/eagle-intel"
if test -n "${EAGLE_YARA_STATIC:-}"; then
    test -f "$EAGLE_YARA_STATIC"
    host_build -I"$root/native/vendor/include" \
        "$root/native/yara.cpp" "$EAGLE_YARA_STATIC" -lm -pthread -o "$destination/lib/eagle/native/eagle-yara"
else
    test "$(pkg-config --modversion yara)" = 4.5.5
    printf '%s\n' 'A pinned static YARA build is required for the runner package' >&2
    exit 1
fi
for architecture in x86_64 i686; do
    if test "$architecture" = x86_64; then bits=64; else bits=32; fi
    "$architecture-w64-mingw32-gcc" -std=c11 -O2 -g -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda/eagle \
        "$root/native/debugger.c" -ldbghelp -o "$destination/lib/eagle/native/eagle-debug$bits.exe"
done
cp "$root/cli.py" "$root/session.py" "$root/protocol.py" "$root/symbols.py" "$root/dap.py" "$root/errors.py" "$root/waits.py" "$root/tracing.py" "$destination/lib/eagle/"
cp -r "$root/engine" "$destination/lib/eagle/"
find "$destination/lib/eagle/engine" -name '*.pyc' -delete
printf '%s\n' '#!/bin/sh' 'root=$(CDPATH= cd -- "$(dirname -- "$0")/../lib/eagle" && pwd)' 'exec python3 "$root/eagle" "$@"' > "$destination/bin/eagle"
cp "$root/eagle" "$destination/lib/eagle/"
cp "$root/COPYING.md" "$destination/lib/eagle/"
mkdir -p "$destination/share/eagle/licenses"
cp "$root/native/vendor/YARA-COPYING" "$root/native/vendor/PEFILE-COPYING" "$destination/share/eagle/licenses/"
cp "$root/sources.json" "$destination/share/eagle/"
chmod 755 "$destination/bin/eagle"
