#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static volatile DWORD result_sink;

static ULONGLONG run_workload(DWORD iterations)
{
    LARGE_INTEGER frequency, start, end;
    CRITICAL_SECTION critical_section;
    WCHAR temp_path[MAX_PATH], temp_file[MAX_PATH], wide_text[64];
    BYTE buffer[256] = {0};
    HBITMAP bitmap, previous_bitmap;
    HANDLE event, file, heap;
    HKEY key;
    HDC dc;
    DWORD i;

    if (!QueryPerformanceFrequency(&frequency)) return 0;
    if (!GetTempPathW(ARRAY_SIZE(temp_path), temp_path)) return 0;
    if (!GetTempFileNameW(temp_path, L"sdp", 0, temp_file)) return 0;

    file = CreateFileW(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    heap = GetProcessHeap();
    dc = CreateCompatibleDC(NULL);
    bitmap = CreateCompatibleBitmap(dc, 32, 32);
    previous_bitmap = SelectObject(dc, bitmap);
    InitializeCriticalSection(&critical_section);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\SodaPGO", 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &key, NULL) != ERROR_SUCCESS)
        key = NULL;

    QueryPerformanceCounter(&start);
    for (i = 0; i < iterations; ++i)
    {
        void *memory;

        EnterCriticalSection(&critical_section);
        memory = HeapAlloc(heap, 0, 128 + (i & 63));
        if (memory)
        {
            memset(memory, i, 128 + (i & 63));
            result_sink += ((BYTE *)memory)[i & 63];
            HeapFree(heap, 0, memory);
        }
        LeaveCriticalSection(&critical_section);

        SetEvent(event);
        result_sink += WaitForSingleObject(event, 0);
        ResetEvent(event);
        result_sink += MultiByteToWideChar(CP_UTF8, 0, "Soda PGO", -1,
                                           wide_text, ARRAY_SIZE(wide_text));
        result_sink += GetFileAttributesW(temp_file);
        PatBlt(dc, i & 15, (i >> 4) & 15, 8, 8, PATCOPY);

        if (!(i & 63))
        {
            DWORD written;

            SetFilePointer(file, 0, NULL, FILE_BEGIN);
            WriteFile(file, buffer, sizeof(buffer), &written, NULL);
            if (key)
                RegSetValueExW(key, L"Iteration", 0, REG_DWORD,
                               (const BYTE *)&i, sizeof(i));
        }
    }
    QueryPerformanceCounter(&end);

    if (key)
    {
        RegCloseKey(key);
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\SodaPGO");
    }
    DeleteCriticalSection(&critical_section);
    SelectObject(dc, previous_bitmap);
    DeleteObject(bitmap);
    DeleteDC(dc);
    CloseHandle(event);
    CloseHandle(file);
    DeleteFileW(temp_file);

    return (end.QuadPart - start.QuadPart) * 1000000 / frequency.QuadPart;
}

int wmain(int argc, WCHAR **argv)
{
    DWORD iterations = 8000;
    ULONGLONG elapsed;

    if (argc == 2 && !wcscmp(argv[1], L"--benchmark")) iterations = 50000;
    elapsed = run_workload(iterations);
    if (!elapsed) return 1;
    wprintf(L"%llu\n", elapsed);
    return 0;
}
