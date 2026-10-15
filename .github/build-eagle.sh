#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner=$(CDPATH= cd -- "${1:?usage: build-eagle.sh RUNNER WORK}" && pwd)
work=${2:?usage: build-eagle.sh RUNNER WORK}
mkdir -p "$work/t"
work=$(CDPATH= cd -- "$work" && pwd)
export TMPDIR="$work/t" TMP="$work/t" TEMP="$work/t"
test -x "$runner/bin/wine"
sh "$root/eagle/build-native.sh" "$work/package" - "$work/native"
cp -a "$work/package/." "$runner/"
python3 "$root/eagle/install.py" "$runner"
mkdir -p "$work/tests"
EAGLE_PACKAGE="$runner" python3 -S "$root/eagle/tests/test_pe_version.py" \
    > "$work/tests/pe-version.log" 2>&1
EAGLE_PACKAGE="$runner" python3 -S "$root/eagle/tests/test_image_inputs.py" \
    > "$work/tests/image-inputs.log" 2>&1
EAGLE_PACKAGE="$runner" python3 -S "$root/eagle/tests/test_debugger_package.py" \
    DebuggerPackageTests.test_provider_dlls_leave_executable_tls_unchanged
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
    directory="$work/tests/s$bits"
    mkdir -p "$directory"
    "$architecture-w64-mingw32-gcc" -O2 -Wall -Wextra -Werror -D__WINESRC__ \
        -I"$runner/include/wine/windows" "$root/eagle/tests/provider_state.c" -o "$directory/target.exe"
    ln -s ../prefix "$directory/prefix"
    export EAGLE_STATE_TEST_ROOT="$directory"
    python3 "$root/eagle/tests/test_provider_state.py" > "$directory/integration.log" 2>&1
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
python3 -S "$root/eagle/tests/test_session_reports.py" > "$work/tests/e/session-reports.log" 2>&1
python3 -S "$root/eagle/tests/test_module_inventory.py" > "$work/tests/e/module-inventory.log" 2>&1
python3 -S "$root/eagle/tests/test_trace_targets.py" > "$work/tests/e/trace-targets.log" 2>&1
python3 -S "$root/eagle/tests/test_export_finalization.py" > "$work/tests/e/export-finalization.log" 2>&1
python3 -S "$root/eagle/tests/test_report_size.py" > "$work/tests/e/report-size.log" 2>&1
python3 -S "$root/eagle/tests/test_trace_memory.py" > "$work/tests/e/trace-memory.log" 2>&1
python3 -S "$root/eagle/tests/test_capture_history.py" > "$work/tests/e/capture-history.log" 2>&1
python3 -S "$root/eagle/tests/test_session_symbols.py" > "$work/tests/e/session-symbols.log" 2>&1
python3 -S "$root/eagle/tests/test_session_compare.py" > "$work/tests/e/comparison.log" 2>&1
python3 -S "$root/eagle/tests/test_symbols_offline.py" > "$work/tests/e/symbols-offline.log" 2>&1
python3 -S "$root/eagle/tests/test_inline_symbols.py" > "$work/tests/e/inline-symbols.log" 2>&1
python3 -S "$root/eagle/tests/test_inline_compression.py" > "$work/tests/e/inline-compression.log" 2>&1
python3 -S "$root/eagle/tests/test_inline_dwo.py" > "$work/tests/e/inline-dwo.log" 2>&1
python3 -S "$root/eagle/tests/test_inline_packages.py" > "$work/tests/e/inline-packages.log" 2>&1
python3 -S "$root/eagle/tests/test_symbols_pdb.py" > "$work/tests/e/symbols-pdb.log" 2>&1
python3 -S "$root/eagle/tests/test_split_dwarf.py" > "$work/tests/e/split-dwarf.log" 2>&1
python3 -S "$root/eagle/tests/test_provenance.py" > "$work/tests/e/provenance.log" 2>&1
python3 -S "$root/eagle/tests/test_capture_startup.py" > "$work/tests/e/capture-startup.log" 2>&1
python3 -S "$root/eagle/tests/test_runner_provenance.py" > "$work/tests/e/runner-provenance.log" 2>&1
python3 -S "$root/eagle/tests/test_symbol_bundle.py" > "$work/tests/e/symbol-bundle.log" 2>&1
python3 -S "$root/eagle/tests/test_symbols_arm.py" > "$work/tests/e/symbols-arm.log" 2>&1
python3 -S "$root/eagle/tests/test_pdb_bundle.py" > "$work/tests/e/pdb-bundle.log" 2>&1
python3 -S "$root/eagle/tests/test_detached_dwarf.py" > "$work/tests/e/detached-dwarf.log" 2>&1
python3 -S "$root/eagle/tests/test_split_bundle.py" > "$work/tests/e/split-bundle.log" 2>&1
python3 -S "$root/eagle/tests/test_split_lookup.py" > "$work/tests/e/split-lookup.log" 2>&1
python3 -S "$root/eagle/tests/test_source_checksums.py" > "$work/tests/e/source-checksums.log" 2>&1
python3 -S "$root/eagle/tests/test_build_sources.py" > "$work/tests/e/build-sources.log" 2>&1
python3 -S "$root/eagle/tests/test_protocol_budget.py" > "$work/tests/e/protocol-budget.log" 2>&1
python3 -S "$root/eagle/tests/test_debugger_package.py" > "$work/tests/e/package.log" 2>&1
python3 -S "$root/eagle/tests/test_native_build.py" > "$work/tests/e/native-build.log" 2>&1
printf '%s\n' 'Eagle package, debugger, automatic tracing and x86/x64 provider controls passed'
