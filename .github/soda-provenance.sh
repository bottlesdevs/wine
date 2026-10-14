#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner=${1:?usage: soda-provenance.sh RUNNER WORK OPTIONS}
work=${2:?usage: soda-provenance.sh RUNNER WORK OPTIONS}
shift 2
test ! -e "$work"
mkdir -p "$work/t" "$work/native"
work=$(CDPATH= cd -- "$work" && pwd)
export TMPDIR="$work/t" TMP="$work/t" TEMP="$work/t"
for module in pe elf; do
    g++ -std=c++17 -O2 -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda \
        "$root/eagle/native/$module.cpp" -o "$work/native/eagle-$module"
done
python3 -S "$root/.github/soda-provenance.py" "$runner" --tools "$work/native" "$@"
