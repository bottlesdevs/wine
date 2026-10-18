#include <windows.h>
#include <stdio.h>

static HANDLE locks[2], ready[2];

static DWORD WINAPI worker(void *argument)
{
    unsigned index = (unsigned)(UINT_PTR)argument;
    DWORD status;
    if (WaitForSingleObject(locks[index], INFINITE) != WAIT_OBJECT_0) return 1;
    SetEvent(ready[index]);
    if (WaitForSingleObject(ready[1-index], INFINITE) != WAIT_OBJECT_0) return 2;
    SetLastError(0x12345678);
    status = WaitForSingleObject(locks[1-index], 500);
    if (GetLastError() != 0x12345678) return 3;
    if (status == WAIT_OBJECT_0) ReleaseMutex(locks[1-index]);
    else if (status != WAIT_TIMEOUT) return 4;
    ReleaseMutex(locks[index]);
    return 0;
}

int main(void)
{
    HANDLE threads[2];
    DWORD code;
    unsigned i;
    for (i = 0; i < 1000; i++)
    {
        HANDLE event = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!event) return 7;
        SetLastError(0x12345678);
        if (!CloseHandle(event) || GetLastError() != 0x12345678) return 8;
    }
    for (i = 0; i < 2; i++)
    {
        locks[i] = CreateMutexA(NULL, FALSE, NULL);
        ready[i] = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!locks[i] || !ready[i]) return 5;
    }
    for (i = 0; i < 2; i++) threads[i] = CreateThread(NULL, 0, worker, (void *)(UINT_PTR)i, 0, NULL);
    if (WaitForMultipleObjects(2, threads, TRUE, 10000) != WAIT_OBJECT_0) return 6;
    for (i = 0; i < 2; i++)
    {
        GetExitCodeThread(threads[i], &code);
        CloseHandle(threads[i]); CloseHandle(ready[i]); CloseHandle(locks[i]);
        if (code) return 10 + code;
    }
    return 0;
}
