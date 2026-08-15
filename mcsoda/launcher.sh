#!/bin/sh

runner=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)

: "${GST_PLUGIN_SYSTEM_PATH_1_0:=$runner/lib/gstreamer-1.0}"
: "${GST_PLUGIN_SCANNER:=$runner/libexec/gstreamer-1.0/gst-plugin-scanner}"
export GST_PLUGIN_SYSTEM_PATH_1_0 GST_PLUGIN_SCANNER

find_d3dmetal_root()
{
    for root in "$@"
    do
        test -n "$root" || continue
        if test -f "$root/external/libd3dshared.dylib" && test -d "$root/wine"
        then
            printf '%s\n' "$root"
            return
        fi
        if test -f "$root/lib/external/libd3dshared.dylib" && test -d "$root/lib/wine"
        then
            printf '%s\n' "$root/lib"
            return
        fi
    done
}

d3dmetal_root=$(find_d3dmetal_root \
    "${MCSODA_D3DMETAL_ROOT:-}" \
    "/Applications/Game Porting Toolkit.app/Contents/Resources/wine/lib" \
    "$HOME/Applications/Game Porting Toolkit.app/Contents/Resources/wine/lib" \
    "/opt/homebrew/opt/game-porting-toolkit/lib" \
    "/usr/local/opt/game-porting-toolkit/lib")

if test -n "$d3dmetal_root"
then
    : "${CX_APPLEGPTK_LIBD3DSHARED_PATH:=$d3dmetal_root/external/libd3dshared.dylib}"
    : "${WINEDLLPATH_PREPEND:=$d3dmetal_root/wine}"
    : "${WINEDLLOVERRIDES:=d3d12,d3d11,d3d10,d3d10core,dxgi=b}"
    : "${CX_ACTIVE_GRAPHICS_BACKEND:=d3dmetal}"
    export CX_APPLEGPTK_LIBD3DSHARED_PATH WINEDLLPATH_PREPEND WINEDLLOVERRIDES
    export CX_ACTIVE_GRAPHICS_BACKEND
fi

exec "$runner/lib/wine/x86_64-unix/wine" "$@"
