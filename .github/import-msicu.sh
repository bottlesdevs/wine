#!/bin/bash

set -euo pipefail

source_dir="$1"
readonly stdio_scan_commit=db0b6dd3c3f3518ebfee4f6e76d76fb2f57828fc
readonly wide_scan_commit=1633d3b502292aad76ac1ded67185de7d92aa2db
readonly math_declarations_commit=d03939d92b54da42427be6f08a9ae2aa20ecdfde
readonly float_types_commit=f97b39dc023d879eda1cbec709f2b81942503055
readonly quick_exit_commit=b824de195a180804b15d9d4e6354321f852d3fbf
readonly div_pe_commit=b4865933b45bcee4d5aed521a6c6efecbc23034f
readonly div_declaration_commit=dfa13310f7afed5d131eef48504a9bcaed45041f
readonly wide_functions_commit=4a9e1e388d432dbe5cce970ed58186d5f1b6b388
readonly long_double_math_commit=8f9fdae8191c369c337fb46d556c0a86ee4c76da
readonly cxx_math_commit=67746887f77582e7ff13a9df94a8f4d4e57bab20
readonly inttypes_commit=1c4081d0bdb78c406f4cc3f3c4cc09fd44950499
readonly number_format_commit=f5e1123a13dedf21bf549866b4d118889b9fd19b
readonly timezone_variables_commit=315bf105473c9cfc74999f3e3880485114ae96bb
readonly exception_macros_commit=3cd70ab702317d964a9033aa217c0ac89ad33250
readonly vcruntime_exception_commit=38f4976e6a156468450453d1c7c7e462c8fd8d86
readonly vcruntime_typeinfo_header_commit=20cdb66f32bbfa59035c65b754e0feb5d8db2d29
readonly vcruntime_new_header_commit=1c12f0b7460b99557337b03af5af34d203233d79
readonly nullptr_commit=ed0e708d61d2ae070ac9df580d27c95e09e41195
readonly exception_classes_commit=6935bd14ee71f5804f4e5f7db5ab3c235ab87c84
readonly cxx_headers_commit=a588cff4173c52012147376111ae754147df5d19
readonly vcruntime_new_commit=fd33d7a1ea5a1bbf3f5bc5438dcd7a89ad25bd09
readonly asm_global_pointer_commit=8c5a8600f7e3936843197b8a40682ccbf29b92ac
readonly gcc_ctors_commit=f03bcaf55fcb6e79f7913cd2d582c34172622987
readonly ucrt_atexit_commit=acc155154086480c0502c0aff7fec760618f2d28
readonly compiler_rt_builtins_commit=0387a68af9cc12dbbfe4c0ff1d085a0fd5b5142e
readonly compiler_rt_mingw_configure_commit=b0e433be9fcd65d0138c489f5a3c7b3dffb8c4b0
readonly compiler_rt_mingw_winegcc_commit=05aefae70b1cbaccd874ff59664800378d8d871b
readonly winecrt_tls_commit=4211b3cef0b6b4883cc6e26278dd9f0e5a779e0b
readonly compiler_rt_emutls_commit=ef09d50622c976e1a5ca64f275de1f5692b27c95
readonly msvcrt_exception_swap_commit=04a4e8d3af539ae1bad594a751720326d51b0550
readonly msvcp_exception_swap_commit=1fa7d4ea9c3f491f219bd12defb27a64c750f380
readonly compiler_rt_i386_commit=5d551aced5727bb1a1561b450fed4ee57d40a93e
readonly compiler_rt_arm64ec_commit=afc3971f2305c9d2fbaef720ab0dc3cb0113ab35
readonly compiler_rt_aarch64_commit=4ce8f0164f2a5cc882c0fea83e32e8a0cdce1c9f
readonly vcruntime_typeinfo_root_commit=36d9bfce5118099f8a624caf9ae19e23fe2f9646
readonly vcruntime_init_thread_commit=07394f94eac8bd338a22c7dcebf2b0d8608c408f
readonly vcruntime_typeinfo_commit=1bc4c614140ec1eb9ee0c40f2b92890142e6f156
readonly assembly_sources_commit=0621c02215d3c78552d05be27bfcd33335512b2c
readonly assembly_subdir_commit=aca0e291c3260a14fc425b7bad6d65787d188445
readonly apisetcconv_commit=6eb8e9e12b80968de77fd8ef55b0b9b54ef51ca2
readonly rtlsupport_cxx_commit=720619188830521709d8324382824535453ff071
readonly libcxx_commit=cedf4bb03f393e82165e8f7f08e599bd505d4c77
readonly libunwind_commit=fcbdb17746e63df4da44a0acfbb3ab815b8803e1
readonly libcxxabi_commit=a100173fb5b44312df5748a10e0317a8517b44df
readonly icucommon_commit=2284a186fecdbf25f33f8e644fcb59fa4865c6d7
readonly icui18n_commit=211f8afc7aa8b77c8ad5ed6df8182a9d073a126d
readonly icudata_commit=1c1d50ce3782b0e15f4aa9d67c4a6b53678b9a04
readonly icu_commit=9d362a4cc190111b101ec056f2da0095840b80c1
readonly icucommon_cleanup_commit=de405dfde3d7695285b3f7e684eef98634e50cbb
readonly icui18n_cleanup_commit=5a6eb78114bfdc584ee5a992f7845ba2729e4bdf
readonly msvcp140_spec_blob=8e769af124276dbc142069d4df62f9b6d2e7ac3b
readonly msvcp140_test_blob=32f06741cfe9d413cbb6ccd921273ea85bc3f5d5
readonly msvcp140_merge_base_blob=c0f4888507d0a4b4d2e5b3da09b381a781ac392d
readonly compiler_rt_merge_base_blob=0a92e3057d08dd7fabbeccbf9035360109e3af67
readonly icucommon_putil_blob=15cff2c1b122c7d131b3c749bffc302d31168a2b
readonly nls_makefile_blob=66ae6cecb00a4515e9d2c1f462d826be994b1e34
readonly icudata_blob=70d2cf94c1518eee3f57087264725934fe70536a
readonly upstream=https://github.com/wine-mirror/wine.git
readonly upstream_remote=soda-msicu-upstream

if git -C "$source_dir" remote get-url "$upstream_remote" >/dev/null 2>&1; then
  git -C "$source_dir" remote set-url "$upstream_remote" "$upstream"
else
  git -C "$source_dir" remote add "$upstream_remote" "$upstream"
fi
git -C "$source_dir" config "remote.$upstream_remote.promisor" true
git -C "$source_dir" config \
  "remote.$upstream_remote.partialclonefilter" blob:limit=1m
origin_promisor="$(git -C "$source_dir" config --bool --get remote.origin.promisor || true)"
if [[ -n "$origin_promisor" ]]; then
  git -C "$source_dir" config remote.origin.promisor false
fi

git -C "$source_dir" fetch --depth=2 --no-tags "$upstream_remote" \
  "$stdio_scan_commit" "$wide_scan_commit" \
  "$math_declarations_commit" "$float_types_commit" \
  "$quick_exit_commit" "$div_pe_commit" "$div_declaration_commit" \
  "$wide_functions_commit" \
  "$long_double_math_commit" "$cxx_math_commit" "$inttypes_commit" \
  "$number_format_commit" "$timezone_variables_commit" \
  "$exception_macros_commit" \
  "$exception_classes_commit"

git -C "$source_dir" fetch --filter=blob:limit=1m --depth=1000 --no-tags \
  "$upstream_remote" \
  "$vcruntime_exception_commit" \
  "$vcruntime_typeinfo_header_commit" "$vcruntime_new_header_commit" \
  "$nullptr_commit" "$cxx_headers_commit" "$vcruntime_new_commit" \
  "$asm_global_pointer_commit" "$gcc_ctors_commit" \
  "$ucrt_atexit_commit" "$compiler_rt_builtins_commit" \
  "$compiler_rt_mingw_configure_commit" \
  "$compiler_rt_mingw_winegcc_commit" \
  "$winecrt_tls_commit" "$compiler_rt_emutls_commit" \
  "$msvcrt_exception_swap_commit" "$msvcp_exception_swap_commit" \
  "$compiler_rt_i386_commit" "$compiler_rt_arm64ec_commit" \
  "$compiler_rt_aarch64_commit" \
  "$vcruntime_typeinfo_root_commit" "$vcruntime_init_thread_commit" \
  "$vcruntime_typeinfo_commit" \
  "$assembly_sources_commit" "$assembly_subdir_commit" \
  "$apisetcconv_commit" \
  "$rtlsupport_cxx_commit" "$libcxx_commit" \
  "$libunwind_commit" "$libcxxabi_commit" \
  "$icucommon_commit" "$icui18n_commit" "$icudata_commit" "$icu_commit" \
  "$icucommon_cleanup_commit" "$icui18n_cleanup_commit"

materialize_blob() {
  local commit="$1"
  local path="$2"
  local expected="$3"
  local actual

  actual="$(curl --fail --location --retry 3 \
    "https://raw.githubusercontent.com/wine-mirror/wine/$commit/$path" | \
    git -C "$source_dir" hash-object -w --stdin)"
  test "$actual" = "$expected"
}

materialize_blob "$cxx_math_commit" \
  dlls/msvcp140/msvcp140.spec "$msvcp140_spec_blob"
materialize_blob "$msvcp_exception_swap_commit" \
  dlls/msvcp140/tests/msvcp140.c "$msvcp140_test_blob"
materialize_blob "$icu_commit" \
  libs/icucommon/putil.cpp "$icucommon_putil_blob"
materialize_blob "$icui18n_cleanup_commit" \
  nls/Makefile.in "$nls_makefile_blob"
materialize_blob "$icudata_commit" nls/icudtl.dat "$icudata_blob"

materialize_git_blob() {
  local expected="$1"
  local actual

  actual="$(curl --fail --location --retry 3 \
    -H 'Accept: application/vnd.github.raw+json' \
    "https://api.github.com/repos/wine-mirror/wine/git/blobs/$expected" | \
    git -C "$source_dir" hash-object -w --stdin)"
  test "$actual" = "$expected"
}

materialize_git_blob "$msvcp140_merge_base_blob"
materialize_git_blob "$compiler_rt_merge_base_blob"

git -C "$source_dir" cherry-pick --no-commit \
  "$stdio_scan_commit" "$wide_scan_commit"

git -C "$source_dir" cherry-pick --no-commit \
  "$math_declarations_commit" "$float_types_commit" \
  "$quick_exit_commit" "$div_pe_commit" "$div_declaration_commit" \
  "$wide_functions_commit" \
  "$long_double_math_commit" "$cxx_math_commit" "$inttypes_commit" \
  "$number_format_commit" "$timezone_variables_commit" \
  "$exception_macros_commit"

git -C "$source_dir" cherry-pick --no-commit \
  "$vcruntime_exception_commit" "$vcruntime_typeinfo_header_commit" \
  "$vcruntime_new_header_commit"

git -C "$source_dir" cherry-pick --no-commit "$nullptr_commit"

git -C "$source_dir" cherry-pick --no-commit "$exception_classes_commit"

git -C "$source_dir" cherry-pick --no-commit "$cxx_headers_commit"

git -C "$source_dir" cherry-pick --no-commit "$vcruntime_new_commit"

if git -C "$source_dir" cherry-pick --no-commit "$asm_global_pointer_commit"; then
  printf 'Expected asm pointer conflict for %s\n' "$asm_global_pointer_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = \
  dlls/ntdll/unix/signal_x86_64.c
git -C "$source_dir" checkout --ours -- dlls/ntdll/unix/signal_x86_64.c
git -C "$source_dir" add include/wine/asm.h dlls/ntdll/unix/signal_x86_64.c
git -C "$source_dir" cherry-pick --quit

git -C "$source_dir" cherry-pick --no-commit \
  "$gcc_ctors_commit" "$ucrt_atexit_commit" \
  "$compiler_rt_builtins_commit"

if git -C "$source_dir" cherry-pick --no-commit "$compiler_rt_mingw_configure_commit"; then
  printf 'Expected compiler-rt configure conflict for %s\n' \
    "$compiler_rt_mingw_configure_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = configure
git -C "$source_dir" rm -- configure
git -C "$source_dir" cherry-pick --quit

git -C "$source_dir" cherry-pick --no-commit \
  "$compiler_rt_mingw_winegcc_commit" \
  "$winecrt_tls_commit" "$compiler_rt_emutls_commit" \
  "$msvcrt_exception_swap_commit" "$msvcp_exception_swap_commit" \
  "$compiler_rt_i386_commit" "$compiler_rt_arm64ec_commit" \
  "$compiler_rt_aarch64_commit" \
  "$vcruntime_typeinfo_root_commit" \
  "$vcruntime_init_thread_commit" "$vcruntime_typeinfo_commit"

if git -C "$source_dir" cherry-pick --no-commit "$assembly_sources_commit"; then
  printf 'Expected assembly source conflict for %s\n' \
    "$assembly_sources_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = \
  tools/make_makefiles
git -C "$source_dir" checkout --ours -- tools/make_makefiles
git -C "$source_dir" add tools/make_makefiles tools/makedep.c
git -C "$source_dir" cherry-pick --quit

if git -C "$source_dir" cherry-pick --no-commit "$assembly_subdir_commit"; then
  printf 'Expected assembly subdirectory conflict for %s\n' \
    "$assembly_subdir_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = \
  tools/makedep.c
git -C "$source_dir" checkout --ours -- tools/makedep.c
git -C "$source_dir" apply --unidiff-zero - <<'PATCH'
diff --git a/tools/makedep.c b/tools/makedep.c
--- a/tools/makedep.c
+++ b/tools/makedep.c
@@ -618,0 +619 @@ static int is_subdir_other_arch( const char *name, unsigned int arch )
+    int cpu;
@@ -623,4 +624,3 @@ static int is_subdir_other_arch( const char *name, unsigned int arch )
-    if (!strcmp( dir, "arm64" )) dir = "aarch64";
-    if (!strcmp( dir, "amd64" )) dir = "x86_64";
-    if (native_archs[arch] && !strcmp( dir, archs.str[native_archs[arch]] )) return 0;
-    return strcmp( dir, archs.str[arch] );
+    if ((cpu = get_cpu_from_name( dir )) == -1) return 0;
+    if (native_archs[arch] && cpu == get_cpu_from_name( archs.str[native_archs[arch]] )) return 0;
+    return cpu != get_cpu_from_name( archs.str[arch] );
PATCH
git -C "$source_dir" add tools/makedep.c
git -C "$source_dir" cherry-pick --quit

git -C "$source_dir" cherry-pick --no-commit \
  "$apisetcconv_commit" "$rtlsupport_cxx_commit"

if git -C "$source_dir" cherry-pick --no-commit "$libcxx_commit"; then
  printf 'Expected libc++ configure conflict for %s\n' "$libcxx_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U | sort)" = "configure
configure.ac"
git -C "$source_dir" rm -- configure
sed -i \
  -e '/^<<<<<<< HEAD$/d' \
  -e '/^=======$/d' \
  -e '/^>>>>>>> .* (libs: Import libc++ from upstream LLVM version 8.0.1.)$/d' \
  "$source_dir/configure.ac"
test -z "$(grep -E '^(<<<<<<<|=======|>>>>>>>)' "$source_dir/configure.ac" || true)"
grep -F 'WINE_EXTLIB_FLAGS(COMPILER_RT, compiler-rt, "$wine_compiler_rt_libs")' "$source_dir/configure.ac"
grep -F 'WINE_EXTLIB_FLAGS(CXX, c++, "c++ msvcp140 vcruntime140")' "$source_dir/configure.ac"
git -C "$source_dir" add configure.ac
git -C "$source_dir" cherry-pick --quit

if git -C "$source_dir" cherry-pick --no-commit "$libunwind_commit"; then
  printf 'Expected configure delete conflict for %s\n' "$libunwind_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = configure
git -C "$source_dir" rm -- configure
git -C "$source_dir" cherry-pick --quit

if git -C "$source_dir" cherry-pick --no-commit "$libcxxabi_commit"; then
  printf 'Expected libc++abi conflicts for %s\n' "$libcxxabi_commit" >&2
  exit 1
fi
test "$(git -C "$source_dir" diff --name-only --diff-filter=U | sort)" = "configure
configure.ac"
git -C "$source_dir" rm -- configure
git -C "$source_dir" checkout --ours -- configure.ac
sed -i \
  '/    wine_compiler_rt_libs="compiler-rt"/a\    case "$target" in\
      *mingw*|*-windows-gnu) enable_cppabi="$enable_cppabi,$wine_arch" ;;\
    esac' \
  "$source_dir/configure.ac"
sed -i \
  's|WINE_EXTLIB_FLAGS(CXX, c++, "c++ msvcp140 vcruntime140")|WINE_EXTLIB_FLAGS(CXX, c++, "c++ \\$(CXXABI_PE_LIBS) msvcp140 vcruntime140")\
WINE_EXTLIB_FLAGS(CXXABI, c++abi, "c++abi \\$(UNWIND_PE_LIBS) c++", "-I\\$(top_srcdir)/libs/c++abi/include")|' \
  "$source_dir/configure.ac"
sed -i \
  '/^enable_vcruntime140_1=/i\enable_cppabi=${enable_cppabi:-no}\
enable_unwind=${enable_unwind:-$enable_cppabi}\
if test "$enable_cppabi" = no; then\
  CXX_PE_LIBS="c++ msvcp140 vcruntime140"\
fi' \
  "$source_dir/configure.ac"
sed -i \
  '/WINE_CONFIG_MAKEFILE(libs\/c++)/a\WINE_CONFIG_MAKEFILE(libs/c++abi)' \
  "$source_dir/configure.ac"
git -C "$source_dir" add configure.ac
git -C "$source_dir" cherry-pick --quit

for commit in "$icucommon_commit" "$icui18n_commit"; do
  if git -C "$source_dir" cherry-pick --no-commit "$commit"; then
    printf 'Expected configure delete conflict for %s\n' "$commit" >&2
    exit 1
  fi
  test "$(git -C "$source_dir" diff --name-only --diff-filter=U)" = configure
  git -C "$source_dir" rm -- configure
  git -C "$source_dir" cherry-pick --quit
done

git -C "$source_dir" cherry-pick --no-commit "$icudata_commit"

if git -C "$source_dir" cherry-pick --no-commit "$icu_commit"; then
  printf 'Expected ICU integration conflicts for %s\n' "$icu_commit" >&2
  exit 1
fi
conflicts="$(git -C "$source_dir" diff --name-only --diff-filter=U | sort)"
test "$conflicts" = "configure
configure.ac
dlls/icu/Makefile.in
dlls/icu/icu.spec"

git -C "$source_dir" rm -- configure
git -C "$source_dir" checkout --theirs -- dlls/icu/Makefile.in dlls/icu/icu.spec
git -C "$source_dir" checkout --ours -- configure.ac
sed -i '/    enable_compiler_rt=${enable_compiler_rt:-no}/a\    enable_icu=${enable_icu:-no}' "$source_dir/configure.ac"
git -C "$source_dir" add configure.ac dlls/icu/Makefile.in dlls/icu/icu.spec
git -C "$source_dir" cherry-pick --quit

git -C "$source_dir" cherry-pick --no-commit \
  "$icucommon_cleanup_commit" "$icui18n_cleanup_commit"

for makefile in \
  libs/c++/Makefile.in libs/c++abi/Makefile.in libs/unwind/Makefile.in \
  libs/icucommon/Makefile.in libs/icui18n/Makefile.in; do
  sed -i '/^EXTRADEFS = / s/$/ -D_UCRT/' "$source_dir/$makefile"
  grep -E '^EXTRADEFS = .* -D_UCRT$' "$source_dir/$makefile"
done

sed -i \
  's/^#if _MSVCR_VER < 120 && defined(_USE_32BIT_TIME_T)$/#if _MSVCR_VER < 120 \&\& defined(_USE_32BIT_TIME_T) \&\& !defined(_UCRT)/' \
  "$source_dir/include/msvcrt/time.h"
grep -F '#if _MSVCR_VER < 120 && defined(_USE_32BIT_TIME_T) && !defined(_UCRT)' \
  "$source_dir/include/msvcrt/time.h"

grep -F 'IMPORTS   = $(ICUI18N_PE_LIBS) $(ICUCOMMON_PE_LIBS) $(CXX_PE_LIBS) advapi32' \
  "$source_dir/dlls/icu/Makefile.in"
grep -F 'enable_icu=${enable_icu:-no}' "$source_dir/configure.ac"
grep -F 'WINE_CONFIG_MAKEFILE(dlls/icu)' "$source_dir/configure.ac"
test ! -e "$source_dir/libs/icucommon/icuplug.cpp"
test ! -e "$source_dir/libs/icui18n/vtzone.cpp"
test -s "$source_dir/nls/icudtl.dat"
test -s "$source_dir/include/msvcrt/cstddef"
test -s "$source_dir/include/msvcrt/string"
test -s "$source_dir/libs/c++/Makefile.in"
test -s "$source_dir/libs/c++abi/Makefile.in"
test -s "$source_dir/libs/unwind/Makefile.in"
grep -F 'src/UnwindRegistersSave.S' "$source_dir/libs/unwind/Makefile.in"
grep -F 'extern "C" {' "$source_dir/include/rtlsupportapi.h"
grep -F 'strendswith( source->name, ".S" )' "$source_dir/tools/makedep.c"
grep -F 'if ((cpu = get_cpu_from_name( dir )) == -1) return 0;' \
  "$source_dir/tools/makedep.c"
test -s "$source_dir/libs/compiler-rt/lib/builtins/emutls.c"
test -s "$source_dir/dlls/winecrt0/tls.c"
test -s "$source_dir/dlls/ucrtbase/atexit.c"
grep -F '@ cdecl -arch=win64 ?__ExceptionPtrSwap@@YAXPEAX0@Z(ptr ptr) __ExceptionPtrSwap' \
  "$source_dir/dlls/msvcp140/msvcp140.spec"

if [[ -n "$origin_promisor" ]]; then
  git -C "$source_dir" config remote.origin.promisor "$origin_promisor"
fi
