#define _WIN32_MSI 500
#include <windows.h>
#include <winternl.h>
#include <msi.h>
#include <stdio.h>

static const WCHAR product[] = L"{79F2A862-F5DE-4C47-8192-9340E7145068}";
static const WCHAR packed_product[] = L"268A2F97ED5F74C4182939047E410586";
static const WCHAR feature[] = L"HandleFixture";
static const WCHAR *paths[] = {
    L"Software\\Classes\\Installer\\Features\\268A2F97ED5F74C4182939047E410586",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\268A2F97ED5F74C4182939047E410586",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Components\\168A2F97ED5F74C4182939047E410586"
};

typedef struct
{
    PVOID object;
    ULONG_PTR owner, value;
    ULONG access;
    USHORT backtrace, type;
    ULONG attributes, reserved;
} OWN_HANDLE_ENTRY;

typedef struct
{
    ULONG_PTR count, reserved;
    OWN_HANDLE_ENTRY entries[1];
} OWN_HANDLE_LIST;

static BOOL own_handle_count(DWORD *count)
{
    ULONG size = 65536, needed;
    OWN_HANDLE_LIST *list;
    NTSTATUS status;
    ULONG_PTR i;
    for (;;)
    {
        if (!(list = HeapAlloc(GetProcessHeap(), 0, size))) return FALSE;
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, list, size, &needed);
        if (status != (NTSTATUS)0xc0000004) break;
        HeapFree(GetProcessHeap(), 0, list);
        size *= 2;
        if (size > 8 * 1024 * 1024) return FALSE;
    }
    if (status)
    {
        printf("FAIL handle enumeration status=%#lx\n", status);
        HeapFree(GetProcessHeap(), 0, list);
        return FALSE;
    }
    if (list->count > (size - 2 * sizeof(ULONG_PTR)) / sizeof(OWN_HANDLE_ENTRY))
    {
        HeapFree(GetProcessHeap(), 0, list);
        return FALSE;
    }
    *count = 0;
    for (i = 0; i < list->count; i++)
        if (list->entries[i].owner == GetCurrentProcessId()) (*count)++;
    HeapFree(GetProcessHeap(), 0, list);
    return TRUE;
}

static LONG set_string(HKEY key, const WCHAR *name, const WCHAR *value)
{
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value,
            (DWORD)((lstrlenW(value) + 1) * sizeof(WCHAR)));
}

int main(void)
{
    static const WCHAR encoded[] = L"IvP4O7lvS@fG1i8-LeTI";
    HKEY keys[3] = {0}, features = NULL;
    BOOL created[3] = {FALSE}, passed = FALSE;
    HANDLE events[16] = {0};
    DWORD before, after, control, disposition;
    unsigned int i;
    LONG status;

    for (i = 0; i < ARRAYSIZE(keys); i++)
    {
        disposition = 0;
        status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, NULL, 0,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &keys[i], &disposition);
        if (status || disposition != REG_CREATED_NEW_KEY)
        {
            printf("FAIL fixture key %u status=%ld disposition=%lu\n", i, status, disposition);
            goto done;
        }
        created[i] = TRUE;
    }
    if (set_string(keys[0], feature, L"") ||
        RegCreateKeyExW(keys[1], L"Features", 0, NULL, 0, KEY_ALL_ACCESS,
                NULL, &features, NULL) ||
        set_string(features, feature, encoded) ||
        set_string(keys[2], packed_product, L"C:\\MsiHandleFixture.dat"))
        goto done;
    RegCloseKey(features);
    features = NULL;
    for (i = 0; i < ARRAYSIZE(keys); i++)
    {
        RegCloseKey(keys[i]);
        keys[i] = NULL;
    }
    for (i = 0; i < 16; i++)
    {
        if (MsiQueryFeatureStateW(product, feature) != INSTALLSTATE_LOCAL)
        {
            puts("FAIL fixture feature state");
            goto done;
        }
    }
    if (!own_handle_count(&before)) goto done;
    for (i = 0; i < ARRAYSIZE(events); i++)
        if (!(events[i] = CreateEventW(NULL, FALSE, FALSE, NULL))) goto done;
    if (!own_handle_count(&control) || control != before + ARRAYSIZE(events))
    {
        puts("FAIL handle counter positive control");
        goto done;
    }
    for (i = 0; i < ARRAYSIZE(events); i++)
    {
        CloseHandle(events[i]);
        events[i] = NULL;
    }
    if (!own_handle_count(&control) || control != before) goto done;
    for (i = 0; i < 100; i++)
        if (MsiQueryFeatureStateW(product, feature) != INSTALLSTATE_LOCAL) goto done;
    if (!own_handle_count(&after)) goto done;
    printf("queries=100 handles_before=%lu handles_after=%lu delta=%ld positive_control=16\n",
            before, after, (LONG)after - (LONG)before);
    passed = after == before;

done:
    for (i = 0; i < ARRAYSIZE(events); i++)
        if (events[i]) CloseHandle(events[i]);
    if (features) RegCloseKey(features);
    for (i = 0; i < ARRAYSIZE(keys); i++)
    {
        if (keys[i]) RegCloseKey(keys[i]);
        if (!created[i]) continue;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY, &keys[i]))
        {
            passed = FALSE;
            continue;
        }
        if (RegDeleteTreeW(keys[i], NULL)) passed = FALSE;
        RegCloseKey(keys[i]);
        if (RegDeleteKeyExW(HKEY_LOCAL_MACHINE, paths[i], KEY_WOW64_64KEY, 0)) passed = FALSE;
    }
    return passed ? 0 : 1;
}
