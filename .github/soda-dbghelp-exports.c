#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    HANDLE process = GetCurrentProcess();
    HMODULE image;
    const char *name = "eagle_export_add";
    DWORD64 address, base, loaded;
    char path[MAX_PATH];
    unsigned exact, offset, failures = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2 || !(image = LoadLibraryA(argv[1]))) return 1;
    address = (DWORD64)(ULONG_PTR)GetProcAddress(image, name);
    if (!address)
    {
        name = "_eagle_export_add";
        address = (DWORD64)(ULONG_PTR)GetProcAddress(image, name);
    }
    if (!address || !GetModuleFileNameA(image, path, sizeof(path))) return 2;
    base = (DWORD64)(ULONG_PTR)image;
    for (exact = 0; exact < 2; exact++)
    {
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                      SYMOPT_FAIL_CRITICAL_ERRORS | (exact ? SYMOPT_EXACT_SYMBOLS : 0));
        if (!SymInitialize(process, "", FALSE)) return 3;
        loaded = SymLoadModuleEx(process, NULL, path, NULL, base, 0, NULL, 0);
        if (!loaded) return 4;
        for (offset = 0; offset < 2; offset++)
        {
            char buffer[sizeof(SYMBOL_INFO) + 1024] = {0};
            SYMBOL_INFO *symbol = (SYMBOL_INFO *)buffer;
            DWORD64 displacement = 0;
            BOOL found;

            symbol->SizeOfStruct = sizeof(*symbol);
            symbol->MaxNameLen = 1023;
            found = SymFromAddr(process, address + offset, &displacement, symbol);
            printf("exact=%u offset=%u found=%d symbol=%s displacement=%llu\n",
                   exact, offset, found, found ? symbol->Name : "", displacement);
            if (!exact && (!found || (strcmp(symbol->Name, "eagle_export_add") &&
                strcmp(symbol->Name, name)) || displacement != offset))
                failures++;
        }
        {
            char buffer[sizeof(SYMBOL_INFO) + 1024] = {0};
            SYMBOL_INFO *symbol = (SYMBOL_INFO *)buffer;
            DWORD64 displacement = 0;
            BOOL found;

            symbol->SizeOfStruct = sizeof(*symbol);
            symbol->MaxNameLen = 1023;
            found = SymFromAddr(process, base - 1, &displacement, symbol);
            printf("exact=%u before_image found=%d\n", exact, found);
            if (found) failures++;
        }
        if (!SymCleanup(process)) return 5;
    }
    FreeLibrary(image);
    printf("failures=%u\n", failures);
    return failures ? 1 : 0;
}
