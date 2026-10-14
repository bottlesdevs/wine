#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:?usage: build-analysis.sh DESTINATION}
case "$destination" in
    /*) ;;
    *) destination="$PWD/$destination" ;;
esac
if test -e "$destination"; then
    printf 'Build destination already exists: %s\n' "$destination" >&2
    exit 1
fi
pkg-config --exists json-c glib-2.0 sqlite3
mkdir -p "$destination/lib/eagle/native"
for module in analysis intel; do
    libraries='json-c glib-2.0'
    if test "$module" = intel; then libraries="$libraries sqlite3"; fi
    g++ -std=c++17 -O2 -g -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda/eagle \
        $(pkg-config --cflags $libraries) "$root/native/$module.cpp" \
        $(pkg-config --libs --static $libraries) \
        -o "$destination/lib/eagle/native/eagle-$module"
done
EAGLE_PACKAGE="$destination" python3 -S "$root/tests/test_analysis_helpers.py"
