#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile int eagle_value = 1;

__declspec(noinline) int eagle_checkpoint(int value)
{
    return value + 7;
}

__declspec(noinline) void eagle_crash(void)
{
    volatile int *pointer = (int *)0;
    *pointer = eagle_checkpoint(4);
}

__declspec(noinline) void eagle_null_call(void)
{
    void (*volatile target)(void) = NULL;
    target();
}

__declspec(noinline) void eagle_null_parent(void)
{
    eagle_null_call();
}

static BOOL handle_null;

static LONG CALLBACK eagle_null_handler(EXCEPTION_POINTERS *exception)
{
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        !exception->ExceptionRecord->ExceptionAddress)
    {
        if (handle_null) ExitProcess(0);
#ifdef _WIN64
        *(ULONG_PTR *)exception->ContextRecord->Rsp = 0;
#else
        *(ULONG_PTR *)exception->ContextRecord->Esp = 0;
#endif
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI eagle_worker(void *argument)
{
    unsigned i;
    for (i = 0; i < 20; i++)
    {
        if (eagle_checkpoint((int)(uintptr_t)argument) != (int)(uintptr_t)argument + 7) return 1;
        Sleep(1);
    }
    return 0;
}

__declspec(noinline) ULONG_PTR eagle_register_arguments(ULONG_PTR first, ULONG_PTR second,
                                                       ULONG_PTR third, ULONG_PTR fourth)
{
    return first ^ second ^ third ^ fourth;
}

enum { DEBUG_WORKERS = 8, DEBUG_LOOKUPS = 128 };

struct debug_channel
{
    unsigned char flags;
    char name[15];
};

static DWORD WINAPI debug_channel_worker(void *argument)
{
    unsigned char (__cdecl *get_flags)(struct debug_channel *);
    unsigned i;
    if (WaitForSingleObject(argument, 10000) != WAIT_OBJECT_0) return 1;
    for (i = 0; i < DEBUG_LOOKUPS; ++i)
    {
        struct debug_channel channel = {0xff, "eagledebug"};
        get_flags = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "__wine_dbg_get_channel_flags");
        if (!get_flags) return 2;
        if (get_flags(&channel) || channel.flags || get_flags(&channel)) return 3;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2 && !strcmp(argv[1], "debug-flags"))
    {
        HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL), workers[DEBUG_WORKERS];
        DWORD code;
        unsigned i;
        FILE *result;
        if (!start) return 31;
        for (i = 0; i < DEBUG_WORKERS; ++i)
            if (!(workers[i] = CreateThread(NULL, 0, debug_channel_worker, start, 0, NULL))) return 32;
        if (!SetEvent(start) || WaitForMultipleObjects(DEBUG_WORKERS, workers, TRUE, 30000) != WAIT_OBJECT_0) return 33;
        for (i = 0; i < DEBUG_WORKERS; ++i)
        {
            if (!GetExitCodeThread(workers[i], &code) || code) return 34;
            CloseHandle(workers[i]);
        }
        CloseHandle(start);
        if (!(result = fopen(argv[2], "w"))) return 35;
        fprintf(result, "{\"threads\":%u,\"lookups\":%u,\"calls\":%u}\n",
                DEBUG_WORKERS, DEBUG_WORKERS * DEBUG_LOOKUPS, DEBUG_WORKERS * DEBUG_LOOKUPS * 2);
        return fclose(result) ? 36 : 0;
    }
    if (argc > 1 && !strcmp(argv[1], "registers"))
    {
        ULONG_PTR third = (ULONG_PTR)0x8877665544332211ULL;
        ULONG_PTR fourth = (ULONG_PTR)0x123456789abcdef0ULL;
        return eagle_register_arguments(0x11, 0x22, third, fourth) == (0x11 ^ 0x22 ^ third ^ fourth) ? 0 : 26;
    }
    if (argc > 1 && (!strcmp(argv[1], "nullcall") || !strcmp(argv[1], "nullcall-handler") ||
        !strcmp(argv[1], "nullcall-handled")))
    {
        handle_null = !strcmp(argv[1], "nullcall-handled");
        if (strcmp(argv[1], "nullcall") && !AddVectoredExceptionHandler(1, eagle_null_handler)) return 23;
        eagle_null_parent();
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "paths"))
    {
        char module[MAX_PATH], directory[MAX_PATH];
        DWORD length;
        FILE *file;
        int result;
        length = GetModuleFileNameA(NULL, module, sizeof(module));
        if (!length || length >= sizeof(module)) return 17;
        length = GetCurrentDirectoryA(sizeof(directory), directory);
        if (!length || length >= sizeof(directory)) return 18;
        if (!(file = fopen(argv[2], "w"))) return 19;
        result = fprintf(file, "%s\n%s\n", module, directory);
        if (fclose(file) || result < 0) return 20;
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "pidalive"))
    {
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, strtoul(argv[2], NULL, 10));
        DWORD status;
        if (!process) return 15;
        status = WaitForSingleObject(process, 0);
        CloseHandle(process);
        return status == WAIT_TIMEOUT ? 0 : 16;
    }
    if (argc > 1 && !strcmp(argv[1], "window"))
    {
        WNDCLASSA cls = {0};
        HWND window;
        MSG message;
        DWORD deadline;
        if (argc > 3)
        {
            HDESK desktop = CreateDesktopA(argv[3], NULL, NULL, 0, GENERIC_ALL, NULL);
            if (!desktop || !SetThreadDesktop(desktop)) return 21;
            if (argc > 5)
            {
                STARTUPINFOA startup = {0};
                PROCESS_INFORMATION process;
                char command[] = "explorer.exe /desktop";
                DWORD status;
                startup.cb = sizeof(startup);
                startup.lpDesktop = argv[3];
                if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) return 24;
                status = WaitForInputIdle(process.hProcess, 60000);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                if (status) return 25;
            }
        }
        cls.lpfnWndProc = DefWindowProcA;
        cls.hInstance = GetModuleHandleA(NULL);
        cls.lpszClassName = "EagleWindowTest";
        if (!RegisterClassA(&cls)) return 13;
        window = CreateWindowA(cls.lpszClassName, "Eagle window test", WS_OVERLAPPEDWINDOW,
                               0, 0, 320, 200, NULL, NULL, cls.hInstance, NULL);
        if (!window) return 14;
        ShowWindow(window, SW_SHOW);
        if (argc > 4)
        {
            FILE *ready = fopen(argv[4], "w");
            if (!ready) return 22;
            if (fclose(ready)) return 23;
        }
        deadline = GetTickCount() + (argc > 2 ? strtoul(argv[2], NULL, 10) : 500);
        while (GetTickCount() < deadline)
        {
            if (argc > 5 && GetFileAttributesA(argv[5]) != INVALID_FILE_ATTRIBUTES) break;
            while (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&message);
                DispatchMessageA(&message);
            }
            Sleep(10);
        }
        DestroyWindow(window);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "waitexit"))
    {
        Sleep(1200);
        return 7;
    }
    if (argc > 1 && !strcmp(argv[1], "stderr"))
    {
        char data[4096];
        const char tail[] = "\neagle stderr tail\xff\0\n";
        DWORD written;
        unsigned i;
        memset(data, 'x', sizeof(data));
        for (i = 0; i < 300; i++)
            if (!WriteFile(GetStdHandle(STD_ERROR_HANDLE), data, sizeof(data), &written, NULL) || written != sizeof(data)) return 29;
        if (!WriteFile(GetStdHandle(STD_ERROR_HANDLE), tail, sizeof(tail) - 1, &written, NULL) || written != sizeof(tail) - 1) return 30;
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "threads"))
    {
        HANDLE workers[2];
        DWORD code;
        unsigned i;
        for (i = 0; i < 2; i++) workers[i] = CreateThread(NULL, 0, eagle_worker, (void *)(uintptr_t)i, 0, NULL);
        if (!workers[0] || !workers[1]) return 10;
        WaitForMultipleObjects(2, workers, TRUE, INFINITE);
        for (i = 0; i < 2; i++)
        {
            GetExitCodeThread(workers[i], &code);
            CloseHandle(workers[i]);
            if (code) return 11;
        }
    }
    if (argc > 1 && !strcmp(argv[1], "attach"))
    {
        printf("%lu\n", GetCurrentProcessId());
        fflush(stdout);
        Sleep(3000);
    }
    if (argc > 1 && !strcmp(argv[1], "crash")) eagle_crash();
    if (argc > 1 && !strcmp(argv[1], "module"))
    {
        HMODULE library = LoadLibraryA("wtsapi32.dll");
        if (!library) return 12;
        FreeLibrary(library);
    }
    if (argc > 1 && (!strcmp(argv[1], "child") || !strcmp(argv[1], "childwait") || !strcmp(argv[1], "childjoin")))
    {
        STARTUPINFOA startup = {0};
        PROCESS_INFORMATION info;
        char path[MAX_PATH], command[MAX_PATH + 32];
        startup.cb = sizeof(startup);
        GetModuleFileNameA(NULL, path, sizeof(path));
        snprintf(command, sizeof(command), "\"%s\" %s", path, !strcmp(argv[1], "childwait") ? "waitexit" : "exit");
        if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info)) return 3;
        if (!strcmp(argv[1], "childjoin"))
        {
            DWORD code = 0;
            BOOL finished = WaitForSingleObject(info.hProcess, 30000) == WAIT_OBJECT_0 &&
                            GetExitCodeProcess(info.hProcess, &code) && code == 7;
            CloseHandle(info.hThread); CloseHandle(info.hProcess);
            if (!finished) return 27;
            return eagle_checkpoint(5) == 12 ? 0 : 28;
        }
        CloseHandle(info.hThread); CloseHandle(info.hProcess);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "wait"))
    {
        Sleep(2000);
    }
    if (argc > 1 && !strcmp(argv[1], "tracewait")) Sleep(8000);
    if (argc > 1 && !strcmp(argv[1], "exit")) return 7;
    eagle_value = 42;
    printf("checkpoint=%d\n", eagle_checkpoint(5));
    if (argc > 2)
    {
        DWORD written;
        HANDLE marker = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (marker == INVALID_HANDLE_VALUE) return 9;
        WriteFile(marker, "alive", 5, &written, NULL); CloseHandle(marker);
    }
    return 0;
}
