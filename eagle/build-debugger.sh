#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:?usage: build-debugger.sh DESTINATION}
case "$destination" in
    /*) ;;
    *) destination="$PWD/$destination" ;;
esac
if test -e "$destination"; then
    printf 'Build destination already exists: %s\n' "$destination" >&2
    exit 1
fi
mkdir -p "$destination/lib/eagle/native" "$destination/bin" "$destination/share/eagle/licenses"
for module in pe elf; do
    g++ -std=c++17 -O2 -g -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda/eagle \
        "$root/native/$module.cpp" -o "$destination/lib/eagle/native/eagle-$module"
done
for architecture in x86_64 i686; do
    if test "$architecture" = x86_64; then bits=64; else bits=32; fi
    "$architecture-w64-mingw32-gcc" -std=c11 -O2 -g -Wall -Wextra -Werror -static \
        -ffile-prefix-map="$root"=/usr/src/soda/eagle \
        "$root/native/debugger.c" -ldbghelp -o "$destination/lib/eagle/native/eagle-debug$bits.exe"
done
for module in cli session protocol symbols dap errors waits tracing; do
    cp "$root/$module.py" "$destination/lib/eagle/"
done
cp "$root/eagle" "$root/COPYING.md" "$destination/lib/eagle/"
cp "$root/native/vendor/PEFILE-COPYING" "$destination/share/eagle/licenses/"
cp "$root/README.md" "$destination/share/eagle/"
printf '%s\n' '#!/bin/sh' 'root=$(CDPATH= cd -- "$(dirname -- "$0")/../lib/eagle" && pwd)' 'exec python3 "$root/eagle" "$@"' > "$destination/bin/eagle"
chmod 755 "$destination/bin/eagle"
