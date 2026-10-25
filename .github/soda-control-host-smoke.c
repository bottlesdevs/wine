#include <windows.h>
#include <cpl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct result
{
    DWORD magic, pid, owner_pid, index, closed;
    WCHAR image[MAX_PATH], parameters[256];
};

#ifdef BUILD_CPL
static struct result result;

static void write_result(void)
{
    WCHAR path[1024];
    HANDLE file;
    DWORD size;

    if (!GetEnvironmentVariableW(L"SODA_CPL_FIXTURE_OUTPUT", path, ARRAYSIZE(path))) return;
    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    WriteFile(file, &result, sizeof(result), &size, NULL);
    CloseHandle(file);
}

__declspec(dllexport) LONG CALLBACK CPlApplet(HWND window, UINT message, LPARAM index, LPARAM data)
{
    switch (message)
    {
    case CPL_INIT:
        return TRUE;
    case CPL_GETCOUNT:
        return 2;
    case CPL_INQUIRE:
    {
        CPLINFO *info = (CPLINFO *)data;
        info->idIcon = info->idName = info->idInfo = CPL_DYNAMIC_RES;
        info->lData = index;
        return 0;
    }
    case CPL_NEWINQUIRE:
    {
        NEWCPLINFOW *info = (NEWCPLINFOW *)data;
        memset(info, 0, sizeof(*info));
        info->dwSize = sizeof(*info);
        info->hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
        info->lData = index;
        lstrcpyW(info->szName, index ? L"Second" : L"First");
        lstrcpyW(info->szInfo, L"Control host fixture");
        return 0;
    }
    case CPL_STARTWPARMSW:
        result.magic = 0x43504c31;
        result.pid = GetCurrentProcessId();
        GetWindowThreadProcessId(window, &result.owner_pid);
        result.index = index;
        GetModuleFileNameW(NULL, result.image, ARRAYSIZE(result.image));
        if (data) lstrcpynW(result.parameters, (WCHAR *)data, ARRAYSIZE(result.parameters));
        write_result();
        Sleep(300);
        return TRUE;
    case CPL_EXIT:
        if (result.magic)
        {
            result.closed = TRUE;
            write_result();
        }
        return 0;
    }
    return 0;
}
#else
static unsigned int checks, failures;

static void check(const char *name, BOOL value)
{
    ++checks;
    if (value) return;
    ++failures;
    printf("%s:failed\n", name);
}

static WORD file_machine(const WCHAR *path)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_FILE_HEADER header;
    DWORD signature, size;
    WORD machine = 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) return 0;
    if (ReadFile(file, &dos, sizeof(dos), &size, NULL) && size == sizeof(dos) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 16 * 1024 * 1024 &&
            SetFilePointer(file, dos.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
            ReadFile(file, &signature, sizeof(signature), &size, NULL) && size == sizeof(signature) &&
            signature == IMAGE_NT_SIGNATURE && ReadFile(file, &header, sizeof(header), &size, NULL) && size == sizeof(header))
        machine = header.Machine;
    CloseHandle(file);
    return machine;
}

int wmain(int argc, WCHAR **argv)
{
    static const struct
    {
        const WCHAR *arguments, *parameters;
        DWORD index;
    } cases[] =
    {
        {L"", L"", 0},
        {L",@1", L"", 1},
        {L",@1,\"fixture value\"", L"fixture value", 1},
        {L",@0,\"value, two & $\"", L"value, two & $", 0},
    };
    WCHAR control[MAX_PATH], command[4096], output[1024], image[MAX_PATH], *name;
    PROCESS_INFORMATION process;
    STARTUPINFOW startup = {0};
    struct result result;
    HANDLE file;
    DWORD length, size, status;
    unsigned int i;

    if (argc != 3) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    length = GetSystemDirectoryW(control, ARRAYSIZE(control));
    if (!length || length > ARRAYSIZE(control) - ARRAYSIZE(L"\\control.exe")) return 3;
    lstrcatW(control, L"\\control.exe");
    GetModuleFileNameW(NULL, image, ARRAYSIZE(image));
    printf("CPL_MACHINES client=%04x control=%04x applet=%04x\n",
            file_machine(image), file_machine(control), file_machine(argv[1]));
    printf("CPL_CONTROL path=%ls\n", control);
    startup.cb = sizeof(startup);
    for (i = 0; i < ARRAYSIZE(cases); ++i)
    {
        if (swprintf(output, ARRAYSIZE(output), L"%ls\\result-%u.bin", argv[2], i) < 0 ||
            swprintf(command, ARRAYSIZE(command), L"\"%ls\" \"%ls\"%ls", control, argv[1], cases[i].arguments) < 0)
            return 4;
        DeleteFileW(output);
        if (!SetEnvironmentVariableW(L"SODA_CPL_FIXTURE_OUTPUT", output)) return 5;
        if (!CreateProcessW(control, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) return 6;
        CloseHandle(process.hThread);
        status = WaitForSingleObject(process.hProcess, 60000);
        if (status != WAIT_OBJECT_0)
        {
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hProcess);
            return 7;
        }
        check("control_exit", GetExitCodeProcess(process.hProcess, &status) && status == 0);
        printf("CPL_CONTROL_EXIT case=%u code=%lu\n", i, (unsigned long)status);
        CloseHandle(process.hProcess);
        file = CreateFileW(output, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        check("applet_output", file != INVALID_HANDLE_VALUE);
        if (file == INVALID_HANDLE_VALUE) continue;
        memset(&result, 0, sizeof(result));
        status = ReadFile(file, &result, sizeof(result), &size, NULL);
        CloseHandle(file);
        check("output_size", status && size == sizeof(result) && result.magic == 0x43504c31);
        if (!status || size != sizeof(result)) continue;
        name = wcsrchr(result.image, '\\');
        check("standard_host", !wcsicmp(name ? name + 1 : result.image, L"rundll32.exe"));
        check("owned_parent", result.owner_pid == result.pid);
        check("applet_index", result.index == cases[i].index);
        check("applet_parameters", !wcscmp(result.parameters, cases[i].parameters));
        check("wait_for_close", result.closed);
        DeleteFileW(output);
    }
    SetEnvironmentVariableW(L"SODA_CPL_FIXTURE_OUTPUT", NULL);
    printf("CPL_HOST_RESULT checks=%u failures=%u\n", checks, failures);
    return failures != 0;
}
#endif
