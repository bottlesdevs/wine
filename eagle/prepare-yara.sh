#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source=${1:?usage: prepare-yara.sh SOURCE BUILD}
build=${2:?usage: prepare-yara.sh SOURCE BUILD}
revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["yara_revision"])' "$root/sources.json")
test "$(git -C "$source" rev-parse HEAD)" = "$revision"
if test -e "$build"; then
    printf 'Build destination already exists: %s\n' "$build" >&2
    exit 1
fi
mkdir -p "$build/source" "$build/build"
build=$(CDPATH= cd -- "$build" && pwd)
git -C "$source" archive --format=tar --output="$build/source.tar" "$revision"
tar -xf "$build/source.tar" -C "$build/source"
rm -- "$build/source.tar"
(cd "$build/source" && autoreconf --force --install)
cd "$build/build"
export CFLAGS="${CFLAGS:--O2 -g} -ffile-prefix-map=$build=/usr/src/soda/eagle-yara"
"$build/source/configure" --disable-shared --enable-static --disable-proc-scan \
    --without-crypto --disable-cuckoo --disable-magic --disable-dotnet
make -j"${EAGLE_BUILD_JOBS:-2}" libyara.la
test -f "$build/build/.libs/libyara.a"
