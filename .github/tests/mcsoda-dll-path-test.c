#include <stdio.h>
#include <windows.h>

#define MCSODA_PE_CHECKSUM 0x4d435344

int main(void)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    HMODULE module = LoadLibraryA("d3d11.dll");

    if (!module)
    {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    dos = (IMAGE_DOS_HEADER *)module;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)module + dos->e_lfanew);
    if (nt->OptionalHeader.CheckSum != MCSODA_PE_CHECKSUM)
    {
        fprintf(stderr, "Loaded DLL checksum: %08lx\n", nt->OptionalHeader.CheckSum);
        return 2;
    }
    puts("McSoda external DLL path test");
    return 0;
}
