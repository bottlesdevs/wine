#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

int wmain(int argc, WCHAR **argv)
{
    HINSTANCE result;
    SYSTEM_INFO info;

    if (argc != 2) return 2;
    if (!lstrcmpW(argv[1], L"--processors"))
    {
        GetSystemInfo(&info);
        wprintf(L"%lu\n", info.dwNumberOfProcessors);
        return 0;
    }
    result = ShellExecuteW(NULL, L"open", argv[1], NULL, NULL, SW_SHOWNORMAL);
    return (INT_PTR)result > 32 ? 0 : 1;
}
