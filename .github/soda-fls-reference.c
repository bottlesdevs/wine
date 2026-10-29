#include <windows.h>
#include <stdio.h>
#include <string.h>

struct callback_record
{
    ULONG_PTR argument, visible;
    DWORD get_error, reset_error;
    BOOL reset_success;
};

static DWORD slot;
static LONG callback_count, reset_done, reset_limit;
static BOOL fiber_set_ok;
static struct callback_record records[32];
static void *primary_fiber;

static void CALLBACK cleanup(void *value)
{
    LONG position = InterlockedIncrement(&callback_count) - 1;
    struct callback_record *record;
    if (position >= 32) return;
    record = records + position;
    record->argument = (ULONG_PTR)value;
    SetLastError(0x12345678);
    record->visible = (ULONG_PTR)FlsGetValue(slot);
    record->get_error = GetLastError();
    if (reset_done < reset_limit)
    {
        ++reset_done;
        record->reset_success = FlsSetValue(slot, (void *)(ULONG_PTR)(reset_done + 1));
        if (!record->reset_success) record->reset_error = GetLastError();
    }
}

static DWORD WINAPI worker(void *argument)
{
    (void)argument;
    return FlsSetValue(slot, (void *)(ULONG_PTR)1) ? 0 : 1;
}

static void WINAPI fiber(void *argument)
{
    (void)argument;
    fiber_set_ok = FlsSetValue(slot, (void *)(ULONG_PTR)1);
    SwitchToFiber(primary_fiber);
}

int main(void)
{
    static const char *names[] = {"free", "free-reset", "thread", "thread-reset", "fiber", "fiber-reset",
                                  "free-reset-four", "free-reset-sixteen", "free-fibers", "free-fibers-reset"};
    unsigned test, i;
    for (test = 0; test < sizeof(names) / sizeof(names[0]); ++test)
    {
        ULONG_PTR parent = 0;
        callback_count = reset_done = 0;
        reset_limit = test == 6 ? 4 : test == 7 ? 16 : test % 2;
        memset(records, 0, sizeof(records));
        if ((slot = FlsAlloc(cleanup)) == FLS_OUT_OF_INDEXES) return 1;
        if (test < 2 || test == 6 || test == 7)
        {
            if (!FlsSetValue(slot, (void *)(ULONG_PTR)1) || !FlsFree(slot)) return 2;
        }
        else if (test < 4)
        {
            HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
            DWORD code;
            if (!thread || WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0 ||
                !GetExitCodeThread(thread, &code) || code) return 3;
            CloseHandle(thread);
            if (!FlsFree(slot)) return 4;
        }
        else
        {
            void *child;
            if (!(primary_fiber = ConvertThreadToFiber(NULL))) return 5;
            if (!FlsSetValue(slot, (void *)(ULONG_PTR)99)) return 6;
            if (!(child = CreateFiber(0, fiber, NULL))) return 7;
            fiber_set_ok = FALSE;
            SwitchToFiber(child);
            if (!fiber_set_ok) return 8;
            if (test >= 8)
            {
                if (!FlsFree(slot)) return 9;
                DeleteFiber(child);
            }
            else
            {
                DeleteFiber(child);
                parent = (ULONG_PTR)FlsGetValue(slot);
                if (!FlsSetValue(slot, NULL) || !FlsFree(slot)) return 9;
            }
            if (!ConvertFiberToThread()) return 10;
        }
        printf("{\"case\":\"%s\",\"callbacks\":%ld,\"parent\":%llu,\"records\":[",
                names[test], callback_count, (unsigned long long)parent);
        for (i = 0; i < (unsigned)callback_count && i < 32; ++i)
        {
            struct callback_record *record = records + i;
            printf("%s{\"argument\":%llu,\"visible\":%llu,\"get_error\":%lu,"
                    "\"reset_success\":%d,\"reset_error\":%lu}", i ? "," : "",
                    (unsigned long long)record->argument, (unsigned long long)record->visible,
                    record->get_error, !!record->reset_success, record->reset_error);
        }
        puts("]}");
    }
    return 0;
}
