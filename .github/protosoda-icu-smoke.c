#include <stdint.h>
#include <stdio.h>
#include <windows.h>

typedef void (__cdecl *u_getVersion_func)(uint8_t *);
typedef void (__cdecl *u_init_func)(int32_t *);
typedef int32_t (__cdecl *ucal_getDefaultTimeZone_func)(WCHAR *, int32_t, int32_t *);

int main(void)
{
    ucal_getDefaultTimeZone_func get_default_timezone;
    u_getVersion_func get_version;
    u_init_func init;
    WCHAR timezone[128];
    uint8_t version[4];
    int32_t status = 0;
    int32_t length;
    HMODULE module;
    union
    {
        FARPROC generic;
        u_getVersion_func get_version;
        u_init_func init;
        ucal_getDefaultTimeZone_func get_default_timezone;
    } symbol;

    if (!(module = LoadLibraryW(L"icu.dll"))) return 1;
    if (!(symbol.generic = GetProcAddress(module, "u_init"))) return 2;
    init = symbol.init;
    if (!(symbol.generic = GetProcAddress(module, "u_getVersion"))) return 3;
    get_version = symbol.get_version;
    if (!(symbol.generic = GetProcAddress(module, "ucal_getDefaultTimeZone"))) return 4;
    get_default_timezone = symbol.get_default_timezone;

    init(&status);
    if (status > 0) return 5;
    get_version(version);
    if (version[0] != 72) return 6;

    status = 0;
    length = get_default_timezone(timezone, (int32_t)ARRAYSIZE(timezone), &status);
    if (status > 0 || length <= 0 || length >= (int32_t)ARRAYSIZE(timezone)) return 7;
    timezone[length] = 0;
    wprintf(L"ICU %u.%u timezone=%ls\n", version[0], version[1], timezone);
    return 0;
}
