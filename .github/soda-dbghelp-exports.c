#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    HANDLE process = GetCurrentProcess();
    HANDLE file;
    HMODULE image;
    const char *name = "eagle_export_add";
    DWORD64 address, base, loaded;
    DWORD image_size;
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
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 6;
    SetEnvironmentVariableA("DBGHELP_DBGOUT", "1");
    base = (DWORD64)(ULONG_PTR)image;
    image_size = ((IMAGE_NT_HEADERS *)((BYTE *)image +
                  ((IMAGE_DOS_HEADER *)image)->e_lfanew))->OptionalHeader.SizeOfImage;
    for (exact = 0; exact < 2; exact++)
    {
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                      SYMOPT_FAIL_CRITICAL_ERRORS | (exact ? SYMOPT_EXACT_SYMBOLS : 0));
        if (!SymInitialize(process, "", FALSE)) return 3;
        IMAGEHLP_MODULE64 module = {0};

        loaded = SymLoadModuleEx(process, file, path, NULL, base, image_size, NULL, 0);
        if (!loaded) return 4;
        printf("exact=%u options=%#lx base=%llx loaded=%llx size=%lu address=%llx path=%s\n",
               exact, SymGetOptions(), base, loaded, image_size, address, path);
        module.SizeOfStruct = sizeof(module);
        if (SymGetModuleInfo64(process, address, &module))
            printf("module type=%u symbols=%lu size=%lu\n",
                   (unsigned)module.SymType, module.NumSyms, module.ImageSize);
        else printf("module error=%lu\n", GetLastError());
        for (offset = 0; offset < 2; offset++)
        {
            char buffer[sizeof(SYMBOL_INFO) + 1024] = {0};
            SYMBOL_INFO *symbol = (SYMBOL_INFO *)buffer;
            DWORD64 displacement = 0;
            BOOL found;

            symbol->SizeOfStruct = sizeof(*symbol);
            symbol->MaxNameLen = 1023;
            SetLastError(0);
            found = SymFromAddr(process, address + offset, &displacement, symbol);
            printf("exact=%u offset=%u found=%d error=%lu symbol=%s displacement=%llu\n",
                   exact, offset, found, GetLastError(), found ? symbol->Name : "", displacement);
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
            found = SymFromAddr(process, base + image_size, &displacement, symbol);
            printf("exact=%u after_image found=%d\n", exact, found);
            if (found) failures++;
        }
        if (!SymCleanup(process)) return 5;
    }
    CloseHandle(file);
    FreeLibrary(image);
    printf("failures=%u\n", failures);
    return failures ? 1 : 0;
}
