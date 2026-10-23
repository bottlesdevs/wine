#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static WCHAR name[] = L"SodaTimeoutProbe";
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static HANDLE stopped;

static void WINAPI handler(DWORD control)
{
    if (control != SERVICE_CONTROL_STOP) return;
    status.dwCurrentState = SERVICE_STOP_PENDING;
    status.dwControlsAccepted = 0;
    SetServiceStatus(status_handle, &status);
    SetEvent(stopped);
}

static void WINAPI service_main(DWORD argc, WCHAR **argv)
{
    (void)argc;
    (void)argv;
    stopped = CreateEventW(NULL, TRUE, FALSE, NULL);
    status_handle = RegisterServiceCtrlHandlerW(name, handler);
    if (!stopped || !status_handle) return;
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(status_handle, &status);
    WaitForSingleObject(stopped, INFINITE);
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    SetServiceStatus(status_handle, &status);
    CloseHandle(stopped);
}

int wmain(int argc, WCHAR **argv)
{
    SERVICE_TABLE_ENTRYW table[] = {{name, service_main}, {NULL, NULL}};
    WCHAR path[MAX_PATH], command[MAX_PATH + 32];
    SC_HANDLE manager, service;
    SERVICE_STATUS current = {0};
    ULONGLONG start;
    DWORD error, failures = 0;
    BOOL ret;

    if (argc != 2) return 2;
    if (!wcscmp(argv[1], L"service"))
    {
        Sleep(15000);
        return !StartServiceCtrlDispatcherW(table);
    }

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager) return 3;
    if (!wcscmp(argv[1], L"install"))
    {
        if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return 4;
        swprintf(command, MAX_PATH + 32, L"\"%ls\" service", path);
        service = CreateServiceW(manager, name, name, SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                command, NULL, NULL, NULL, NULL, NULL);
        error = service ? 0 : GetLastError();
        if (service) CloseServiceHandle(service);
        CloseServiceHandle(manager);
        printf("install error=%lu\n", error);
        return error != 0;
    }
    if (wcscmp(argv[1], L"run-fail") && wcscmp(argv[1], L"run-pass")) return 5;
    service = OpenServiceW(manager, name, SERVICE_ALL_ACCESS);
    if (!service) return 6;
    start = GetTickCount64();
    ret = StartServiceW(service, 0, NULL);
    error = ret ? 0 : GetLastError();
    printf("start success=%d error=%lu elapsed=%llu\n", ret, error, GetTickCount64() - start);
    if (!wcscmp(argv[1], L"run-pass")) failures += !ret;
    else failures += ret || error != ERROR_SERVICE_REQUEST_TIMEOUT;
    if (ret)
    {
        start = GetTickCount64();
        do
        {
            if (!QueryServiceStatus(service, &current)) break;
            if (current.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(100);
        } while (GetTickCount64() - start < 10000);
        printf("ready state=%lu\n", current.dwCurrentState);
        if (current.dwCurrentState != SERVICE_RUNNING) ++failures;
        if (!ControlService(service, SERVICE_CONTROL_STOP, &current))
        {
            printf("stop error=%lu\n", GetLastError());
            ++failures;
        }
        start = GetTickCount64();
        do
        {
            if (!QueryServiceStatus(service, &current)) break;
            if (current.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(100);
        } while (GetTickCount64() - start < 10000);
        if (current.dwCurrentState != SERVICE_STOPPED) ++failures;
    }
    if (!DeleteService(service))
    {
        printf("delete error=%lu\n", GetLastError());
        ++failures;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    printf("SERVICE_START_RESULT failures=%lu\n", failures);
    return failures != 0;
}
