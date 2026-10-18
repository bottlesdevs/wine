#!/bin/sh
set -eu
source=${1:?usage: prepare-yara.sh SOURCE BUILD}
build=${2:?usage: prepare-yara.sh SOURCE BUILD}
test "$(git -C "$source" rev-parse HEAD)" = f44a8958e88daa75d765a52a68876f2286d57a51
source=$(CDPATH= cd -- "$source" && pwd)
mkdir -p "$build"
build=$(CDPATH= cd -- "$build" && pwd)
if ! test -x "$source/configure"; then
    (cd "$source" && autoreconf --force --install)
fi
cd "$build"
"$source/configure" --disable-shared --enable-static --disable-proc-scan \
    --without-crypto --disable-cuckoo --disable-magic --disable-dotnet
make -j"${EAGLE_BUILD_JOBS:-4}"
test -f "$build/.libs/libyara.a"
