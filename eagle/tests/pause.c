#define _WIN32_WINNT 0x0601
#include <windows.h>
static unsigned break_calls;
static BOOL break_result = TRUE;
static BOOL WINAPI break_process(HANDLE process)
{
    if (process != (HANDLE)1) return FALSE;
    ++break_calls;
    SetLastError(ERROR_ACCESS_DENIED);
    return break_result;
}
#define DebugBreakProcess break_process
#define main collector_main
#include "../native/debugger.c"
#undef main
#undef DebugBreakProcess

int main(void)
{
    DEBUG_EVENT pending = {0};
    DWORD status = DBG_CONTINUE;
    processes[0] = (struct process){.id = 7, .handle = (HANDLE)1, .initial_break = TRUE};
    if (command("pause", NULL, NULL) || break_calls || !processes[0].pause_requested) return 1;
    processes[0].initial_break = FALSE;
    processes[0].pause_requested = FALSE;
    if (command("pause", NULL, NULL) || break_calls != 1 || !processes[0].pause_requested) return 2;
    processes[0].pause_requested = FALSE;
    if (command("pause", &pending, &status) || break_calls != 1 || processes[0].pause_requested) return 3;
    break_result = FALSE;
    if (command("pause", NULL, NULL) || break_calls != 2 || processes[0].pause_requested) return 4;
    puts("initial pause deferred; running pause requested; pending pause unchanged; failed request cleared");
    return 0;
}
