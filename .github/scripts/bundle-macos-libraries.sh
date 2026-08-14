#!/bin/bash

set -euo pipefail

prefix="${1:?missing installation prefix}"
external_dir="$prefix/lib/mcsoda"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/mcsoda-bundle.XXXXXX")"

cleanup()
{
    rm -rf "$work_dir"
}

trap cleanup EXIT
mkdir -p "$external_dir"

is_macho()
{
    file -b "$1" | grep -q 'Mach-O'
}

list_macho_files()
{
    find "$prefix" -type f -print | while IFS= read -r file_path
    do
        if is_macho "$file_path"; then printf '%s\n' "$file_path"; fi
    done
}

copy_dependency()
{
    dependency="$1"
    target="$external_dir/$(basename "$dependency")"

    if test -e "$target"
    then
        source_hash="$(shasum -a 256 "$dependency" | cut -d ' ' -f 1)"
        target_hash="$(shasum -a 256 "$target" | cut -d ' ' -f 1)"
        test "$source_hash" = "$target_hash" || {
            echo "Conflicting libraries named $(basename "$dependency")" >&2
            exit 1
        }
        return
    fi

    cp -L "$dependency" "$target"
    chmod u+w "$target"
}

while true
do
    : > "$work_dir/dependencies"
    list_macho_files | while IFS= read -r file_path
    do
        otool -L "$file_path" | tail -n +2 | awk '{print $1}' | while IFS= read -r dependency
        do
            case "$dependency" in
                /usr/local/*|/opt/homebrew/*) printf '%s\n' "$dependency" >> "$work_dir/dependencies" ;;
            esac
        done
    done

    sort -u "$work_dir/dependencies" -o "$work_dir/dependencies"
    copied=0
    while IFS= read -r dependency
    do
        test -n "$dependency" || continue
        if ! test -e "$external_dir/$(basename "$dependency")"; then copied=1; fi
        copy_dependency "$dependency"
    done < "$work_dir/dependencies"
    test "$copied" -eq 1 || break
done

list_macho_files | while IFS= read -r file_path
do
    otool -L "$file_path" | tail -n +2 | awk '{print $1}' | while IFS= read -r dependency
    do
        case "$dependency" in
            /usr/local/*|/opt/homebrew/*)
                install_name_tool -change "$dependency" "@rpath/$(basename "$dependency")" "$file_path"
                ;;
        esac
    done

    otool -l "$file_path" | awk '
        $1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
        in_rpath && $1 == "path" { print $2; in_rpath = 0 }
    ' | while IFS= read -r rpath
    do
        case "$rpath" in
            /usr/local/*|/opt/homebrew/*) install_name_tool -delete_rpath "$rpath" "$file_path" ;;
        esac
    done

    relative_dir="$(perl -MFile::Spec -e 'print File::Spec->abs2rel($ARGV[0], $ARGV[1])' "$external_dir" "$(dirname "$file_path")")"
    if ! otool -l "$file_path" | awk '
        $1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
        in_rpath && $1 == "path" { print $2; in_rpath = 0 }
    ' | grep -Fxq "@loader_path/$relative_dir"
    then
        install_name_tool -add_rpath "@loader_path/$relative_dir" "$file_path"
    fi
done

find "$external_dir" -type f -print | while IFS= read -r file_path
do
    if is_macho "$file_path"; then install_name_tool -id "@rpath/$(basename "$file_path")" "$file_path"; fi
done

list_macho_files | while IFS= read -r file_path
do
    codesign --force --sign - --timestamp=none "$file_path"
done

list_macho_files | while IFS= read -r file_path
do
    if otool -L "$file_path" | tail -n +2 | awk '{print $1}' | grep -Eq '^(/usr/local/|/opt/homebrew/)'
    then
        echo "Unbundled Homebrew dependency in $file_path" >&2
        otool -L "$file_path" >&2
        exit 1
    fi
done
