#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "eagle_trace.h"

int main(int argc, char **argv)
{
    const GUID guid = {0x12345678, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}};
    DWORD before_error, after_error;
    ULONG before_status, after_status;
    unsigned i, failures = 0;
    FILE *file;

    if (argc != 2) return 1;
    if (!(file = fopen(argv[1], "wb"))) return 2;
    for (i = 0; i < 8; i++)
    {
        NtCurrentTeb()->LastStatusValue = 0xc0000022;
        SetLastError(0x12345678);
        before_error = GetLastError();
        before_status = NtCurrentTeb()->LastStatusValue;
        if (i == 0) eagle_trace_enabled(15);
        if (i == 1) eagle_trace_event(1, "state.probe", S_OK, 0, 0, 0, 0, NULL, NULL, NULL);
        if (i == 2) eagle_trace_com("state.probe", S_OK, NULL, NULL, NULL, 0, 0, NULL);
        if (i == 3) eagle_trace_wait("WaitBegin", NULL, 0, 0);
        if (i == 4) eagle_trace_event(1, "state.probe", S_OK, 0, 0, 0, 0, NULL, &guid, NULL);
        if (i == 5) eagle_trace_com("state.probe", S_OK, &guid, &guid, NULL, 0, 0, NULL);
        if (i == 6) eagle_trace_event(1, "state.probe", S_OK, 0, 0, 0, 0, NULL, (void *)1, NULL);
        if (i == 7) eagle_trace_com("state.probe", S_OK, (void *)1, (void *)1, NULL, 0, 0, NULL);
        after_error = GetLastError();
        after_status = NtCurrentTeb()->LastStatusValue;
        fprintf(file, "%u %08x %08x %08x %08x\n", i, (unsigned)before_error,
                (unsigned)after_error, (unsigned)before_status, (unsigned)after_status);
        if (before_error != after_error || before_status != after_status) failures++;
    }
    if (fclose(file)) return 3;
    return failures ? 4 : 0;
}
