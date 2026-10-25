#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static unsigned int checks, failures;

static void check(const char *name, LONG result, LONG expected)
{
    checks++;
    if (result != expected) failures++;
    printf("{\"case\":\"%s\",\"result\":%ld,\"expected\":%ld}\n", name, result, expected);
}

static void remove_file(const WCHAR *path)
{
    WCHAR log[MAX_PATH];
    unsigned int i;
    BOOL removed = DeleteFileW(path);
    check("cleanup", removed || GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : GetLastError(), 0);
    for (i = 1; i <= 2; i++)
    {
        swprintf(log, MAX_PATH, L"%ls.LOG%u", path, i);
        removed = DeleteFileW(log);
        check("cleanup_log", removed || GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : GetLastError(), 0);
    }
}

int wmain(int argc, WCHAR **argv)
{
    static const WCHAR text[] = L"application hive fixture";
    static const BYTE binary[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
    WCHAR path[MAX_PATH], invalid[MAX_PATH], missing[MAX_PATH], data[64];
    char ansi[MAX_PATH], value[64];
    HKEY root = NULL, subkey = NULL, second = NULL;
    DWORD number = 0x12345678, actual = 0, type = 0, size, written;
    DWORD children = 0, values = 0;
    HANDLE file;
    LONG ret;

    if ((argc != 2 && argc != 3) || lstrlenW(argv[1]) > MAX_PATH - 40) return 2;
    swprintf(path, MAX_PATH, L"%ls\\application.dat", argv[1]);
    swprintf(invalid, MAX_PATH, L"%ls\\invalid.dat", argv[1]);
    swprintf(missing, MAX_PATH, L"%ls\\missing-parent\\application.dat", argv[1]);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(invalid) != INVALID_FILE_ATTRIBUTES) return 2;
    if (!WideCharToMultiByte(CP_ACP, 0, path, -1, ansi, sizeof(ansi), NULL, NULL)) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);

    ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0);
    check("create", ret, ERROR_SUCCESS);
    if (ret) goto cleanup;
    ret = RegQueryInfoKeyW(root, NULL, NULL, NULL, &children, NULL, NULL,
                          &values, NULL, NULL, NULL, NULL);
    check("root_info", ret, ERROR_SUCCESS);
    if (ret) goto close;
    check("empty_subkeys", children, 0);
    check("empty_values", values, 0);
    ret = RegCreateKeyExW(root, L"Fixture\\Child", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &subkey, NULL);
    check("create_subkey", ret, ERROR_SUCCESS);
    if (ret) goto close;
    check("write_number", RegSetValueExW(subkey, L"Number", 0, REG_DWORD,
          (const BYTE *)&number, sizeof(number)), ERROR_SUCCESS);
    check("write_text", RegSetValueExW(subkey, L"Text", 0, REG_SZ,
          (const BYTE *)text, sizeof(text)), ERROR_SUCCESS);
    check("write_binary", RegSetValueExW(subkey, L"Binary", 0, REG_BINARY,
          binary, sizeof(binary)), ERROR_SUCCESS);
    size = 0;
    check("query_size", RegQueryValueExW(subkey, L"Text", NULL, &type, NULL, &size), ERROR_SUCCESS);
    check("text_type", type, REG_SZ);
    check("text_size", size, sizeof(text));
    size = sizeof(WCHAR);
    check("short_buffer", RegQueryValueExW(subkey, L"Text", NULL, &type,
          (BYTE *)data, &size), ERROR_MORE_DATA);
    check("short_buffer_size", size, sizeof(text));
    check("flush", RegFlushKey(root), ERROR_SUCCESS);
    ret = RegLoadAppKeyW(path, &second, KEY_READ, 0, 0);
    printf("{\"case\":\"second_open\",\"result\":%ld}\n", ret);
    if (!ret)
    {
        check("second_info", RegQueryInfoKeyW(second, NULL, NULL, NULL, &children,
              NULL, NULL, NULL, NULL, NULL, NULL, NULL), ERROR_SUCCESS);
        check("second_close", RegCloseKey(second), ERROR_SUCCESS);
        second = NULL;
    }
    check("close_subkey", RegCloseKey(subkey), ERROR_SUCCESS);
    subkey = NULL;
    check("close_root", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;
    if (argc == 3)
        check("snapshot", CopyFileW(path, argv[2], TRUE) ? 0 : GetLastError(), ERROR_SUCCESS);

    ret = RegLoadAppKeyW(path, &root, KEY_READ, REG_PROCESS_APPKEY, 0);
    check("reopen", ret, ERROR_SUCCESS);
    if (ret) goto cleanup;
    ret = RegOpenKeyExW(root, L"Fixture\\Child", 0, KEY_READ, &subkey);
    check("reopen_subkey", ret, ERROR_SUCCESS);
    if (ret) goto close;
    size = sizeof(actual);
    check("read_number", RegQueryValueExW(subkey, L"Number", NULL, &type,
          (BYTE *)&actual, &size), ERROR_SUCCESS);
    check("number_type", type, REG_DWORD);
    check("number_value", actual, number);
    size = sizeof(data);
    check("read_text", RegQueryValueExW(subkey, L"Text", NULL, &type,
          (BYTE *)data, &size), ERROR_SUCCESS);
    check("text_value", size == sizeof(text) && !memcmp(data, text, sizeof(text)), TRUE);
    size = sizeof(data);
    check("read_binary", RegQueryValueExW(subkey, L"Binary", NULL, &type,
          (BYTE *)data, &size), ERROR_SUCCESS);
    check("binary_type", type, REG_BINARY);
    check("binary_value", size == sizeof(binary) && !memcmp(data, binary, sizeof(binary)), TRUE);
    check("read_only_write", RegSetValueExW(subkey, L"Number", 0, REG_DWORD,
          (const BYTE *)&number, sizeof(number)), ERROR_ACCESS_DENIED);
    check("read_only_delete", RegDeleteValueW(subkey, L"Number"), ERROR_ACCESS_DENIED);
    check("close_read_subkey", RegCloseKey(subkey), ERROR_SUCCESS);
    subkey = NULL;
    check("close_read_root", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;

    ret = RegLoadAppKeyA(ansi, &root, KEY_READ, 0, 0);
    check("ansi_open", ret, ERROR_SUCCESS);
    if (ret) goto cleanup;
    ret = RegOpenKeyExA(root, "Fixture\\Child", 0, KEY_READ, &subkey);
    check("ansi_subkey", ret, ERROR_SUCCESS);
    if (ret) goto close;
    size = sizeof(value);
    check("ansi_value", RegQueryValueExA(subkey, "Text", NULL, &type,
          (BYTE *)value, &size), ERROR_SUCCESS);
    check("ansi_text", size == sizeof("application hive fixture") &&
          !memcmp(value, "application hive fixture", sizeof("application hive fixture")), TRUE);

close:
    if (subkey) check("final_close_subkey", RegCloseKey(subkey), ERROR_SUCCESS);
    if (root) check("final_close_root", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;
    check("reserved", RegLoadAppKeyW(path, &root, KEY_READ, 0, 1), ERROR_INVALID_PARAMETER);
    check("null_file", RegLoadAppKeyW(NULL, &root, KEY_READ, 0, 0), ERROR_INVALID_PARAMETER);
    ret = RegLoadAppKeyW(missing, &root, KEY_READ, 0, 0);
    check("missing_parent", ret, ERROR_PATH_NOT_FOUND);
    if (!ret) RegCloseKey(root);
    root = NULL;
    file = CreateFileW(invalid, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 2;
    if (!WriteFile(file, "invalid", 7, &written, NULL) || written != 7)
    {
        CloseHandle(file);
        DeleteFileW(invalid);
        return 2;
    }
    CloseHandle(file);
    ret = RegLoadAppKeyW(invalid, &root, KEY_READ, 0, 0);
    printf("{\"case\":\"invalid_file\",\"result\":%ld}\n", ret);
    check("reject_invalid_file", ret != ERROR_SUCCESS, TRUE);
    if (!ret) RegCloseKey(root);
    remove_file(invalid);
cleanup:
    remove_file(path);
    printf("{\"checks\":%u,\"failures\":%u}\n", checks, failures);
    return failures ? 1 : 0;
}
