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

prepare_d3dmetal_dll_path()
{
    root=$1
    overlay="${TMPDIR:-/tmp}/mcsoda-d3dmetal-$(id -u)"

    umask 077
    for arch in i386-windows x86_64-windows
    do
        install -d "$overlay/wine/$arch"
        for module in d3d10.dll d3d10_1.dll d3d10core.dll d3d11.dll d3d12.dll d3d12core.dll dxgi.dll
        do
            source_module="$root/wine/$arch/$module"
            target_module="$overlay/wine/$arch/$module"
            if test -f "$source_module"
            then
                rm -f "$target_module"
                ln -s "$source_module" "$target_module"
            else
                rm -f "$target_module"
            fi
        done
    done

    printf '%s\n' "$overlay/wine"
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
    : "${WINEDLLPATH_PREPEND:=$(prepare_d3dmetal_dll_path "$d3dmetal_root")}"
    : "${WINEDLLOVERRIDES:=d3d12,d3d12core,d3d11,d3d10,d3d10_1,d3d10core,dxgi=b}"
    : "${CX_ACTIVE_GRAPHICS_BACKEND:=d3dmetal}"
    export CX_APPLEGPTK_LIBD3DSHARED_PATH WINEDLLPATH_PREPEND WINEDLLOVERRIDES
    export CX_ACTIVE_GRAPHICS_BACKEND
fi

exec "$runner/lib/wine/x86_64-unix/wine" "$@"
