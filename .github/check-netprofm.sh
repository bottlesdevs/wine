#!/bin/bash
# AI-assisted with Amp. SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ${1-} != --inside ]]; then
    source_dir=$(realpath "${1:?usage: $0 WINE_SOURCE WINE_BUILD NEW_LOG_DIRECTORY}")
    build_dir=$(realpath "${2:?missing Wine build directory}")
    logs=$(realpath -m "${3:?log directory must not already exist}")
    wrapper=$(realpath "$0")
    # These paths must survive the private /tmp mount. Resolve symlinks before
    # checking, and reject before creating logs or running privileged commands.
    for path in "$source_dir" "$build_dir" "$logs" "$wrapper"; do
        if [[ $path == /tmp || $path == /tmp/* ]]; then
            echo "Paths under /tmp are unavailable after isolation: $path. Use a location outside /tmp." >&2
            exit 1
        fi
    done
    mkdir "$logs"
    # The imported tests use fixed /tmp names. A private mount prevents them
    # from removing another run's prefixes, markers, sockets, or logs.
    scratch=$(mktemp -d)
    chmod 1777 "$scratch"
    trap 'sudo -n rm -rf -- "$scratch"' EXIT
    sudo -n unshare --mount --propagation private bash -c '
        set -e
        mount --bind "$1" /tmp
        shift
        exec setpriv --reuid="$1" --regid="$2" --init-groups \
            env HOME="$3" bash "$4" --inside "$5" "$6" "$7"
    ' bash "$scratch" "$(id -u)" "$(id -g)" "$HOME" \
        "$wrapper" "$source_dir" "$build_dir" "$logs"
    exit
fi

source_dir=$2
build_dir=$3
logs=$4
export WINEDEBUG=-all
unset DISPLAY
export WINEPREFIX=/tmp/soda-nlm-ordinary
if file "$build_dir/dlls/ntdll/ntdll.so" | grep -q 'ELF 32-bit'; then
    export WINEARCH=win32
    export CC="${CC:-cc} -m32"
    export PKG_CONFIG_LIBDIR=/usr/lib/i386-linux-gnu/pkgconfig:/usr/share/pkgconfig
    # --with-wine64 deliberately shares build tools rather than compiling them.
    # Give the fixture-only winegcc invocations the same tools as the Makefile.
    if [[ ! -e $build_dir/tools ]]; then
        tools_dir=$(sed -n 's/^wine64dir = //p' "$build_dir/Makefile")
        if [[ $tools_dir != /* ]]; then tools_dir="$build_dir/$tools_dir"; fi
        tools_dir=$(realpath "$tools_dir")
        [[ -x $tools_dir/tools/winegcc/winegcc && -x $tools_dir/tools/winebuild/winebuild ]]
        ln -s "$tools_dir/tools" "$build_dir/tools"
    fi
fi
trap '"$build_dir/server/wineserver" -k 2>/dev/null || true' EXIT
status=0
for module in netprofm nsi iphlpapi; do
    if make -C "$build_dir" "dlls/$module/tests/testclean" >"$logs/$module.log" 2>&1 &&
        make -C "$build_dir" RUNTESTFLAGS='-P wine' "dlls/$module/tests/test" >>"$logs/$module.log" 2>&1; then
        echo "PASS: $module"
    else
        echo "FAIL: $module (see $logs/$module.log)"
        status=1
    fi
done
"$build_dir/server/wineserver" -k
"$build_dir/server/wineserver" -w
rm -rf "$WINEPREFIX"

if "$source_dir/dlls/netprofm/tests/dynamic-cleanup.sh" >"$logs/dynamic-cleanup.log" 2>&1; then
    echo 'PASS: dynamic-cleanup'
else
    echo "FAIL: dynamic-cleanup (see $logs/dynamic-cleanup.log)"
    status=1
fi
for test in dynamic-network topology-policy ipv6-route-availability adversarial nsi-faults; do
    if "$source_dir/dlls/netprofm/tests/$test.sh" "$build_dir" >"$logs/$test.log" 2>&1; then
        echo "PASS: $test"
    else
        echo "FAIL: $test (see $logs/$test.log)"
        status=1
    fi
done
if [[ -f $build_dir/dlls/netprofm/tests/i386-windows/netprofm_test.exe &&
      -f $build_dir/dlls/netprofm/tests/x86_64-windows/netprofm_test.exe ]]; then
    if "$source_dir/dlls/netprofm/tests/dynamic-network.sh" "$build_dir" \
        "$build_dir/dlls/netprofm/tests/i386-windows/netprofm_test.exe" \
        >"$logs/dynamic-network-i386.log" 2>&1; then
        echo 'PASS: dynamic-network-i386'
    else
        echo "FAIL: dynamic-network-i386 (see $logs/dynamic-network-i386.log)"
        status=1
    fi
fi
if grep -q '^#define SONAME_LIBDBUS_1 ' "$build_dir/include/config.h"; then
    for test in reachability-network bus-stalls; do
        if sh "$source_dir/dlls/netprofm/tests/$test.sh" "$build_dir" \
            >"$logs/$test.log" 2>&1; then
            echo "PASS: $test"
        else
            echo "FAIL: $test (see $logs/$test.log)"
            status=1
        fi
    done
fi
if [[ $status == 0 ]]; then echo 'All selected NLM/NSI/IP Helper checks passed.'; fi
exit "$status"
