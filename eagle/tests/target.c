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

int main(int argc, char **argv)
{
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
        cls.lpfnWndProc = DefWindowProcA;
        cls.hInstance = GetModuleHandleA(NULL);
        cls.lpszClassName = "EagleWindowTest";
        if (!RegisterClassA(&cls)) return 13;
        window = CreateWindowA(cls.lpszClassName, "Eagle window test", WS_OVERLAPPEDWINDOW,
                               0, 0, 320, 200, NULL, NULL, cls.hInstance, NULL);
        if (!window) return 14;
        ShowWindow(window, SW_SHOW);
        deadline = GetTickCount() + (argc > 2 ? strtoul(argv[2], NULL, 10) : 500);
        while (GetTickCount() < deadline)
        {
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
    if (argc > 1 && (!strcmp(argv[1], "child") || !strcmp(argv[1], "childwait")))
    {
        STARTUPINFOA startup = {0};
        PROCESS_INFORMATION info;
        char path[MAX_PATH], command[MAX_PATH + 32];
        startup.cb = sizeof(startup);
        GetModuleFileNameA(NULL, path, sizeof(path));
        snprintf(command, sizeof(command), "\"%s\" %s", path, !strcmp(argv[1], "childwait") ? "waitexit" : "exit");
        if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info)) return 3;
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
