#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "eagle_identity_trace.h"

static unsigned failures;

static void emit(ULONG request, unsigned operation, unsigned stage, HRESULT result)
{
    SetLastError(0x12345678);
    NtCurrentTeb()->LastStatusValue = 0xc0000022;
    eagle_trace_identity(request, operation, stage, result, __builtin_return_address(0));
    if (GetLastError() != 0x12345678 || NtCurrentTeb()->LastStatusValue != 0xc0000022) failures++;
}

int main(int argc, char **argv)
{
    FILE *file;
    if (argc != 2) return 1;
    emit(41, 2, EAGLE_IDENTITY_BEGIN, E_PENDING);
    emit(41, 2, EAGLE_IDENTITY_TRANSPORT, S_OK);
    emit(41, 2, EAGLE_IDENTITY_RESPONSE, S_OK);
    emit(41, 2, EAGLE_IDENTITY_COMPLETE, S_OK);
    emit(42, 3, EAGLE_IDENTITY_BEGIN, E_PENDING);
    emit(42, 3, EAGLE_IDENTITY_TRANSPORT, E_ACCESSDENIED);
    emit(42, 3, EAGLE_IDENTITY_COMPLETE, E_ACCESSDENIED);
    emit(0, 2, EAGLE_IDENTITY_BEGIN, S_OK);
    emit(43, 99, EAGLE_IDENTITY_BEGIN, S_OK);
    emit(44, 2, 99, S_OK);
    if (!(file = fopen(argv[1], "wb"))) return 2;
    fprintf(file, "%u %lu %u\n", (unsigned)(sizeof(void *) * 8), GetCurrentProcessId(), failures);
    if (fclose(file)) return 3;
    return failures ? 4 : 0;
}
