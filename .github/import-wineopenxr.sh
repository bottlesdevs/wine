#!/bin/bash

set -euo pipefail

wine_source="$1"
openxr_source="$2"
target="$wine_source/dlls/wineopenxr"

test -f "$wine_source/configure.ac"
test -f "$openxr_source/openxr_loader.c"
test ! -e "$target"

cp -a -- "$openxr_source" "$target"
