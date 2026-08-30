#include <windows.h>
#include <shellapi.h>

int wmain(int argc, WCHAR **argv)
{
    HINSTANCE result;

    if (argc != 2) return 2;
    result = ShellExecuteW(NULL, L"open", argv[1], NULL, NULL, SW_SHOWNORMAL);
    return (INT_PTR)result > 32 ? 0 : 1;
}
