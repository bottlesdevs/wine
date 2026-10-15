#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

static void reset_state(void)
{
    NtCurrentTeb()->LastStatusValue = 0xc0000022;
    SetLastError(0x12345678);
}

static void record_state(FILE *output, const char *operation)
{
    DWORD error = GetLastError();
    ULONG status = NtCurrentTeb()->LastStatusValue;
    fprintf(output, "%s %08lx %08lx\n", operation, error, status);
}

int main(int argc, char **argv)
{
    typedef int (__cdecl *value_function)(void);
    typedef FARPROC (WINAPI *lookup_function)(HMODULE, LPCSTR);
    union { FARPROC generic; lookup_function lookup; } base_lookup;
    char long_name[601];
    WCHAR path[1024];
    HMODULE module;
    union { FARPROC generic; value_function value; } function;
    FILE *output;
    unsigned i;

    if (argc < 3 || !(output = fopen(argv[2], "w"))) return 1;
    if (!MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, path, ARRAY_SIZE(path))) return 2;
    reset_state();
    module = LoadLibraryExW(L"C:\\private-path-sentinel\\EagleMissingFixture.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module || GetLastError() != ERROR_MOD_NOT_FOUND) return 3;
    record_state(output, "missing_w");
    reset_state();
    module = LoadLibraryExA("EagleMissingAnsi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module || GetLastError() != ERROR_MOD_NOT_FOUND) return 4;
    record_state(output, "missing_a");
    reset_state();
    if (LoadLibraryW(L"EagleMissingPlainW.dll") || GetLastError() != ERROR_MOD_NOT_FOUND) return 5;
    record_state(output, "plain_w");
    reset_state();
    if (LoadLibraryA("EagleMissingPlainA.dll") || GetLastError() != ERROR_MOD_NOT_FOUND) return 6;
    record_state(output, "plain_a");
    reset_state();
    if (LoadLibraryExW(NULL, NULL, 0) || GetLastError() != ERROR_INVALID_PARAMETER) return 7;
    record_state(output, "null_name");
    reset_state();
    module = LoadLibraryExW(path, NULL, 0);
    if (!module) return 8;
    record_state(output, "load");
    base_lookup.generic = GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GetProcAddress");
    if (!base_lookup.generic) return 19;
    reset_state();
    function.generic = base_lookup.lookup(module, "EagleLoaderValue");
    if (!function.generic || function.value() != 73) return 20;
    record_state(output, "base_named");
    reset_state();
    function.generic = GetProcAddress(module, "EagleLoaderValue");
    if (!function.generic || function.value() != 73) return 9;
    record_state(output, "named");
    reset_state();
    function.generic = GetProcAddress(module, (const char *)9);
    if (!function.generic || function.value() != 91) return 10;
    record_state(output, "ordinal");
    reset_state();
    if (GetProcAddress(module, "EagleMissingExport") || GetLastError() != ERROR_PROC_NOT_FOUND) return 11;
    record_state(output, "missing_export");
    reset_state();
    if (GetProcAddress(module, (const char *)99) || GetLastError() != ERROR_PROC_NOT_FOUND) return 12;
    record_state(output, "missing_ordinal");
    reset_state();
    if (GetProcAddress(module, "EagleMissing\"Quote") || GetLastError() != ERROR_PROC_NOT_FOUND) return 13;
    record_state(output, "quoted_export");
    memset(long_name, 'X', 200);long_name[200] = 0;
    reset_state();
    if (GetProcAddress(module, long_name) || GetLastError() != ERROR_PROC_NOT_FOUND) return 21;
    record_state(output, "truncated_export");
    memset(long_name, 'Y', 600);long_name[600] = 0;
    reset_state();
    if (GetProcAddress(module, long_name) || GetLastError() != ERROR_PROC_NOT_FOUND) return 22;
    record_state(output, "overlong_export");
    if (argc > 3 && !strcmp(argv[3], "budget"))
        for (i = 0; i < 4100; ++i)
            if (!(i % 2 ? GetProcAddress(module, "EagleLoaderValue") : base_lookup.lookup(module, "EagleLoaderValue"))) return 14;
    reset_state();
    if (!FreeLibrary(module)) return 15;
    record_state(output, "unload");
    reset_state();
    if (FreeLibrary(NULL) || GetLastError() != ERROR_INVALID_HANDLE) return 16;
    record_state(output, "null_module");
    reset_state();
    if (LoadPackagedLibrary(L"EaglePackageFixture.dll", 0) || GetLastError() != APPMODEL_ERROR_NO_PACKAGE) return 17;
    record_state(output, "packaged");
    if (fclose(output)) return 18;
    puts("LOADER_PROVIDER_OK");
    return 0;
}
