#ifndef __WINE_EAGLE_TRACE_H
#define __WINE_EAGLE_TRACE_H

#include <stdio.h>
#include <stdlib.h>
#include "windef.h"
#include "winbase.h"

static inline BOOL eagle_trace_enabled(unsigned mask)
{
    static LONG enabled = -1;
    DWORD saved_error = GetLastError();
    LONG value = InterlockedCompareExchange(&enabled, -1, -1);
    if (value == -1)
    {
        char text[16];
        value = GetEnvironmentVariableA("EAGLE_PROVIDER_MASK", text, sizeof(text)) ? strtoul(text, NULL, 0) : 0;
        InterlockedExchange(&enabled, value);
    }
    SetLastError(saved_error);
    return (value & mask) != 0;
}

static inline void eagle_trace_event(unsigned mask, const char *name, HRESULT result,
                                     LONG a, LONG b, ULONG c, ULONG d, const WCHAR *subject, const GUID *requested_iid, const void *caller)
{
    char text[768], label[128], iid[40] = "";
    GUID guid;
    SIZE_T read;
    unsigned i;
    DWORD saved_error;
    saved_error = GetLastError();
    if (!eagle_trace_enabled(mask)) return;
    for (i = 0; subject && subject[i] && i < sizeof(label) - 1; i++)
    {
        WCHAR ch = subject[i];
        label[i] = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' ? ch : '?';
    }
    label[i] = 0;
    if (requested_iid && ReadProcessMemory(GetCurrentProcess(), requested_iid, &guid, sizeof(guid), &read) && read == sizeof(guid))
        snprintf(iid, sizeof(iid), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    snprintf(text, sizeof(text), "EAGLE/1 {\"provider\":%u,\"event\":\"%s\",\"hresult\":\"0x%08lx\",\"a\":%ld,\"b\":%ld,\"c\":%lu,\"d\":%lu,\"subject\":\"%s\",\"iid\":\"%s\",\"caller\":\"%p\"}", mask, name, result, a, b, c, d, label, iid, caller);
    OutputDebugStringA(text);
    SetLastError(saved_error);
}

static inline void eagle_trace_guid(const GUID *value, char *output, unsigned size)
{
    GUID guid;
    SIZE_T read;
    output[0] = 0;
    if (value && ReadProcessMemory(GetCurrentProcess(), value, &guid, sizeof(guid), &read) && read == sizeof(guid))
        snprintf(output, size, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

static inline void eagle_trace_com(const char *name, HRESULT result, const GUID *clsid, const GUID *requested_iid,
                                    const void *object, DWORD context, DWORD count, const void *caller)
{
    char text[768], class_name[40], iid[40];
    DWORD saved_error = GetLastError();
    if (!eagle_trace_enabled(4)) return;
    eagle_trace_guid(clsid, class_name, sizeof(class_name));
    eagle_trace_guid(requested_iid, iid, sizeof(iid));
    snprintf(text, sizeof(text), "EAGLE/1 {\"provider\":4,\"event\":\"%s\",\"hresult\":\"0x%08lx\",\"clsid\":\"%s\",\"iid\":\"%s\",\"object\":\"%p\",\"context\":%lu,\"count\":%lu,\"caller\":\"%p\"}", name, result, class_name, iid, object, context, count, caller);
    OutputDebugStringA(text);
    SetLastError(saved_error);
}

static inline void eagle_trace_wait(const char *name, HANDLE object, DWORD value, DWORD timeout)
{
    static __thread BOOL busy;
    static LONG emitted;
    char text[384];
    LONG count;
    DWORD saved_error = GetLastError();
    if (busy || !eagle_trace_enabled(8) || !IsDebuggerPresent()) return;
    count = InterlockedIncrement(&emitted);
    if (count > 50001) return;
    busy = TRUE;
    if (count == 50001)
        snprintf(text, sizeof(text), "EAGLE/1 {\"provider\":8,\"event\":\"ObserverBudgetExceeded\",\"limit\":50000}");
    else
        snprintf(text, sizeof(text), "EAGLE/1 {\"provider\":8,\"event\":\"%s\",\"object\":\"%p\",\"value\":%lu,\"timeout_ms\":%lu}", name, object, value, timeout);
    OutputDebugStringA(text);
    busy = FALSE;
    SetLastError(saved_error);
}

#endif
