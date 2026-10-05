#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner=$(CDPATH= cd -- "${1:?usage: build-eagle.sh RUNNER WORK}" && pwd)
work=${2:?usage: build-eagle.sh RUNNER WORK}
mkdir -p "$work/t"
work=$(CDPATH= cd -- "$work" && pwd)
export TMPDIR="$work/t" TMP="$work/t" TEMP="$work/t"
test -x "$runner/bin/wine"
sh "$root/eagle/build-debugger.sh" "$work/package"
cp -a "$work/package/." "$runner/"
python3 "$root/eagle/install.py" "$runner"
mkdir -p "$work/tests"
WINEPREFIX="$work/tests/prefix" WINEDEBUG=-all "$runner/bin/wine" wineboot -u
export EAGLE_CANDIDATE="$runner" EAGLE_WAIT_TEST_ROOT="$work/tests"
for architecture in x86_64 i686; do
    if test "$architecture" = x86_64; then bits=64; else bits=32; fi
    directory="$work/tests/$bits"
    mkdir -p "$directory"
    "$architecture-w64-mingw32-gcc" -O0 -g -gdwarf-4 -Wall -Wextra -Werror \
        "$root/eagle/tests/wait_provider.c" -o "$directory/target.exe"
    ln -s ../prefix "$directory/prefix"
    export EAGLE_WAIT_TEST_ROOT="$directory"
    python3 "$root/eagle/tests/test_wait_provider.py" > "$directory/integration.log" 2>&1
    directory="$work/tests/p$bits"
    mkdir -p "$directory"
    "$architecture-w64-mingw32-gcc" -O0 -g -gdwarf-4 -Wall -Wextra -Werror         "$root/eagle/tests/provider.c" -lole32 -lruntimeobject -ldwrite -o "$directory/provider$bits.exe"
    ln -s ../prefix "$directory/prefix"
    export EAGLE_PROVIDER_TEST_ROOT="$directory" EAGLE_PROVIDER_BITS="$bits"
    python3 "$root/eagle/tests/test_providers.py" > "$directory/integration.log" 2>&1
    directory="$work/tests/c$bits"
    mkdir -p "$directory"
    "$architecture-w64-mingw32-gcc" -O0 -g -gdwarf-4 -Wall -Wextra -Werror         "$root/eagle/tests/com_provider.c" -lole32 -o "$directory/target.exe"
    ln -s ../prefix "$directory/prefix"
    export EAGLE_COM_TEST_ROOT="$directory"
    python3 "$root/eagle/tests/test_com_provider.py" > "$directory/integration.log" 2>&1
done
directory="$work/tests/d"
mkdir -p "$directory"
ln -s ../prefix "$directory/prefix"
for architecture in x86_64 i686; do
    if test "$architecture" = x86_64; then bits=64; else bits=32; fi
    "$architecture-w64-mingw32-gcc" -O0 -g -gdwarf-4 -Wall -Wextra -Werror         "$root/eagle/tests/target.c" -o "$directory/target$bits.exe"
done
export EAGLE_TEST_ROOT="$directory" EAGLE_PACKAGE="$runner" EAGLE_TEST_WINE="$runner/bin/wine"
python3 "$root/eagle/tests/integration.py" > "$directory/integration.log" 2>&1
directory="$work/tests/t"
mkdir -p "$directory"
ln -s ../prefix "$directory/prefix"
cp "$work/tests/d/target32.exe" "$work/tests/d/target64.exe" "$directory/"
cp "$work/tests/64/target.exe" "$directory/wait.exe"
export EAGLE_TRACE_TEST_ROOT="$directory"
python3 "$root/eagle/tests/test_tracing.py" > "$directory/integration.log" 2>&1
mkdir -p "$work/tests/e"
export EAGLE_TRACE_EXPORT_ROOT="$work/tests/e"
python3 -S "$root/eagle/tests/test_trace_export.py" > "$work/tests/e/integration.log" 2>&1
python3 -S "$root/eagle/tests/test_debugger_package.py" > "$work/tests/e/package.log" 2>&1
printf '%s\n' 'Eagle package, debugger, automatic tracing and x86/x64 provider controls passed'
