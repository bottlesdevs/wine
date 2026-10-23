#include <windows.h>
#include <stdio.h>

int main(void)
{
    const char *dlls[] = {"mapi32.dll", "mapistub.dll"};
    const char *names[] = {"LAUNCHWIZARD", "LaunchWizard@20", "LaunchWizard"};
    HRESULT (WINAPI *launch)(HWND, ULONG, LPCSTR *, ULONG, LPSTR);
    HMODULE module;
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
            launch = (void *)GetProcAddress(module, names[j]);
            if (!launch)
            {
                printf("missing %s!%s\n", dlls[i], names[j]);
                ++failures;
                continue;
            }
            hr = launch(NULL, 0, NULL, 0, NULL);
            printf("%s!%s=%#lx\n", dlls[i], names[j], hr);
            if (hr != E_FAIL) ++failures;
        }
        FreeLibrary(module);
    }
    printf("MAPI_RUNTIME_RESULT failures=%u\n", failures);
    return failures != 0;
}
