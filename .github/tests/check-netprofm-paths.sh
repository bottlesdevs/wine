#!/bin/bash
# AI-assisted with Amp. SPDX-License-Identifier: LGPL-2.1-or-later
# Path validation and shared-tool resolution; no Wine build is required.
set -euo pipefail
wrapper=$(realpath "$(dirname "$0")/../check-netprofm.sh")
outside=$(mktemp -d /var/tmp/soda-nlm-paths.XXXXXX)
inside=$(mktemp -d /tmp/soda-nlm-paths.XXXXXX)
trap 'rm -rf -- "$outside" "$inside"' EXIT
mkdir "$outside/source" "$outside/build" "$inside/source" "$inside/build"

reject_before_logs()
{
    local script=$1 source=$2 build=$3 logs=$4
    if bash "$script" "$source" "$build" "$logs" > "$outside/result.log" 2>&1; then
        echo "FAIL: accepted an input hidden by the private /tmp mount" >&2
        exit 1
    fi
    if [[ -e $logs ]]; then
        echo "FAIL: created logs before rejecting hidden inputs" >&2
        cat "$outside/result.log" >&2
        exit 1
    fi
}

reject_before_logs "$wrapper" "$inside/source" "$outside/build" "$outside/source-logs"
reject_before_logs "$wrapper" "$outside/source" "$inside/build" "$outside/build-logs"
reject_before_logs "$wrapper" "$outside/source" "$outside/build" "$inside/new-logs"
ln -s "$inside/source" "$outside/source-link"
reject_before_logs "$wrapper" "$outside/source-link" "$outside/build" "$outside/symlink-logs"
cp "$wrapper" "$inside/check-netprofm.sh"
reject_before_logs "$inside/check-netprofm.sh" "$outside/source" "$outside/build" "$outside/wrapper-logs"
echo 'PASS: source/build/log/symlink/wrapper paths under /tmp rejected before log creation.'

# Exercise the real inside entry point with a minimal build fixture. OS/build
# commands are stand-ins: this checks path resolution, not Wine or network QA.
# In particular, the child must never clean actual fixed-name /tmp prefixes.
mkdir -p "$outside/bin" "$outside/source/checkout" "$outside/source/dlls/netprofm/tests" \
    "$outside/build32/dlls/ntdll" "$outside/build32/include" "$outside/build32/server" \
    "$outside/build64/tools/winegcc" "$outside/build64/tools/winebuild" "$outside/tool-logs"
printf '#!/bin/sh\nexit 0\n' > "$outside/bin/noop"
printf '#!/bin/sh\necho "ELF 32-bit"\n' > "$outside/bin/file"
chmod +x "$outside/bin/noop" "$outside/bin/file"
ln -s noop "$outside/bin/make"
ln -s noop "$outside/bin/rm"
ln -s "$outside/bin/noop" "$outside/build32/server/wineserver"
ln -s "$outside/bin/noop" "$outside/build64/tools/winegcc/winegcc"
ln -s "$outside/bin/noop" "$outside/build64/tools/winebuild/winebuild"
touch "$outside/build32/dlls/ntdll/ntdll.so" "$outside/build32/include/config.h"
printf '#!/bin/sh\ntest -x "%s/tools/winegcc/winegcc" && test -x "%s/tools/winebuild/winebuild"\n' "\$1" "\$1" \
    > "$outside/source/dlls/netprofm/tests/tools-check"
chmod +x "$outside/source/dlls/netprofm/tests/tools-check"
ln -s "$outside/bin/noop" "$outside/source/dlls/netprofm/tests/dynamic-cleanup.sh"
for fixture in dynamic-network topology-policy ipv6-route-availability adversarial nsi-faults; do
    ln -s tools-check "$outside/source/dlls/netprofm/tests/$fixture.sh"
done
for tools in ../build64 "$outside/build64"; do
    printf 'wine64dir = %s\n' "$tools" > "$outside/build32/Makefile"
    if ! (cd "$outside/source/checkout" && PATH="$outside/bin:$PATH" \
          bash "$wrapper" --inside "$outside/source" "$outside/build32" "$outside/tool-logs") \
          > "$outside/result.log" 2>&1; then
        echo "FAIL: shared tools unavailable with wine64dir=$tools" >&2
        cat "$outside/result.log" >&2
        exit 1
    fi
    rm "$outside/build32/tools"
done
echo 'PASS: relative and absolute wine64dir work from an unrelated working directory.'
