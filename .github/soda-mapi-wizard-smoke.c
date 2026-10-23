#include <windows.h>
#include <stdio.h>

int main(void)
{
    const char *dlls[] = {"mapi32.dll", "mapistub.dll"};
    const char *names[] = {"LAUNCHWIZARD", "LaunchWizard@20", "LaunchWizard"};
    HRESULT (WINAPI *launch)(HWND, ULONG, LPCSTR *, ULONG, LPSTR);
    HMODULE module;
    FARPROC exports[3];
    HRESULT hr;
    unsigned int i, j, failures = 0;

    for (i = 0; i < ARRAYSIZE(dlls); ++i)
    {
        module = LoadLibraryA(dlls[i]);
        if (!module)
        {
            printf("load %s failed: %lu\n", dlls[i], GetLastError());
            ++failures;
            continue;
        }
        for (j = 0; j < ARRAYSIZE(names); ++j)
        {
            exports[j] = GetProcAddress(module, names[j]);
            if (!exports[j])
            {
                printf("missing %s!%s\n", dlls[i], names[j]);
                ++failures;
            }
        }
        if (exports[0] && exports[1] && exports[2])
        {
            if (exports[0] != exports[1] || exports[1] != exports[2]) ++failures;
            launch = (void *)exports[2];
            hr = launch(NULL, 0, NULL, 0, NULL);
            printf("%s LaunchWizard=%#lx\n", dlls[i], hr);
            if (hr != E_FAIL) ++failures;
        }
        FreeLibrary(module);
    }
    printf("MAPI_RUNTIME_RESULT failures=%u\n", failures);
    return failures != 0;
}
