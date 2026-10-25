#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sddl.h>
#ifdef REGISTRY_HIVE_CODEC
#include "registry_hive.h"
#endif

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

static BOOL copy_hive_snapshot(const WCHAR *path, const WCHAR *destination)
{
    WCHAR source_log[MAX_PATH], destination_log[MAX_PATH];
    unsigned int i;

    if (!CopyFileW(path, destination, TRUE)) return FALSE;
    for (i = 1; i <= 2; i++)
    {
        swprintf(source_log, MAX_PATH, L"%ls.LOG%u", path, i);
        if (GetFileAttributesW(source_log) == INVALID_FILE_ATTRIBUTES) continue;
        swprintf(destination_log, MAX_PATH, L"%ls.LOG%u", destination, i);
        if (!CopyFileW(source_log, destination_log, TRUE)) return FALSE;
    }
    return TRUE;
}

static void test_security(HKEY root, HKEY child)
{
    SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR first = NULL, second = NULL;
    WCHAR *first_text = NULL, *second_text = NULL;
    DWORD first_size = 0, second_size = 0;
    LONG ret;

    check("security_root_size", RegGetKeySecurity(root, info, NULL, &first_size), ERROR_INSUFFICIENT_BUFFER);
    check("security_child_size", RegGetKeySecurity(child, info, NULL, &second_size), ERROR_INSUFFICIENT_BUFFER);
    if (!first_size || !second_size) return;
    first = malloc(first_size);
    second = malloc(second_size);
    if (!first || !second) { check("security_allocate", 1, 0); goto done; }
    ret = RegGetKeySecurity(root, info, first, &first_size);
    check("security_root_read", ret, ERROR_SUCCESS);
    if (ret) goto done;
    ret = RegGetKeySecurity(child, info, second, &second_size);
    check("security_child_read", ret, ERROR_SUCCESS);
    if (ret) goto done;
    ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(first, SDDL_REVISION_1, info, &first_text, NULL);
    check("security_root_text", ret, TRUE);
    if (!ret) goto done;
    ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(second, SDDL_REVISION_1, info, &second_text, NULL);
    check("security_child_text", ret, TRUE);
    if (!ret) goto done;
    check("security_matches", !lstrcmpW(first_text, second_text), TRUE);
    check("security_root_change", RegSetKeySecurity(root, DACL_SECURITY_INFORMATION, first), ERROR_ACCESS_DENIED);
    check("security_child_change", RegSetKeySecurity(child, DACL_SECURITY_INFORMATION, second), ERROR_ACCESS_DENIED);
done:
    LocalFree(first_text);
    LocalFree(second_text);
    free(first);
    free(second);
}

static LONG run_child(const WCHAR *path, DWORD options, DWORD expected)
{
    WCHAR executable[MAX_PATH], command[2 * MAX_PATH + 80];
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD length, result;

    length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (!length || length >= MAX_PATH) return ERROR_INVALID_NAME;
    swprintf(command, sizeof(command) / sizeof(*command), L"\"%ls\" --child \"%ls\" %lu %lu",
             executable, path, options, expected);
    startup.cb = sizeof(startup);
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) return GetLastError();
    CloseHandle(process.hThread);
    result = WaitForSingleObject(process.hProcess, 20000);
    if (result != WAIT_OBJECT_0)
    {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
        CloseHandle(process.hProcess);
        return ERROR_TIMEOUT;
    }
    if (!GetExitCodeProcess(process.hProcess, &result)) result = GetLastError();
    CloseHandle(process.hProcess);
    return result;
}

static int child_access(const WCHAR *path, DWORD options, DWORD expected)
{
    HKEY root = NULL;
    DWORD value = 12345;
    LONG ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, options, 0);

    if (ret != (LONG)expected) return 1;
    if (ret) return 0;
    ret = RegSetValueExW(root, L"CrossProcess", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    if (RegCloseKey(root)) return 1;
    return ret ? 1 : 0;
}

static void test_processes(const WCHAR *path)
{
    HKEY root = NULL;
    DWORD value = 0, size = sizeof(value), type = 0;
    LONG ret;

    ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0);
    check("process_private_load", ret, ERROR_SUCCESS);
    if (ret) return;
    check("process_private_child", run_child(path, 0, ERROR_SHARING_VIOLATION), ERROR_SUCCESS);
    check("process_private_close", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;
    ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, 0, 0);
    check("process_shared_load", ret, ERROR_SUCCESS);
    if (ret) return;
    check("process_shared_child", run_child(path, 0, ERROR_SUCCESS), ERROR_SUCCESS);
    check("process_shared_query", RegQueryValueExW(root, L"CrossProcess", NULL, &type,
          (BYTE *)&value, &size), ERROR_SUCCESS);
    check("process_shared_type", type, REG_DWORD);
    check("process_shared_value", value, 12345);
    check("process_shared_close", RegCloseKey(root), ERROR_SUCCESS);
}

static void test_lifetime(const WCHAR *path)
{
    HKEY root = NULL, child = NULL, second = NULL, reader = NULL;
    DWORD number = 0x11223344, actual = 0, size, type = 0;
    LONG ret;

    ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0);
    check("lifetime_load", ret, ERROR_SUCCESS);
    if (ret) return;
    ret = RegOpenKeyExW(root, L"Fixture\\Child", 0, KEY_ALL_ACCESS, &child);
    check("lifetime_child", ret, ERROR_SUCCESS);
    if (ret) goto done;
    test_security(root, child);
    check("lifetime_close_root", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;
    check("lifetime_child_write", RegSetValueExW(child, L"Lifetime", 0, REG_DWORD,
          (const BYTE *)&number, sizeof(number)), ERROR_SUCCESS);
    check("lifetime_child_flush", RegFlushKey(child), ERROR_SUCCESS);
    ret = RegLoadAppKeyW(path, &second, KEY_READ, 0, 0);
    check("lifetime_child_keeps_private", ret, ERROR_SHARING_VIOLATION);
    if (!ret) RegCloseKey(second);
    second = NULL;
    check("lifetime_close_child", RegCloseKey(child), ERROR_SUCCESS);
    child = NULL;

    ret = RegLoadAppKeyW(path, &root, KEY_ALL_ACCESS, 0, 0);
    check("shared_load", ret, ERROR_SUCCESS);
    if (ret) goto done;
    ret = RegLoadAppKeyW(path, &second, KEY_ALL_ACCESS, 0, 0);
    check("shared_second_load", ret, ERROR_SUCCESS);
    if (ret) goto done;
    check("shared_write", RegSetValueExW(root, L"Shared", 0, REG_DWORD,
          (const BYTE *)&number, sizeof(number)), ERROR_SUCCESS);
    size = sizeof(actual);
    check("shared_read", RegQueryValueExW(second, L"Shared", NULL, &type,
          (BYTE *)&actual, &size), ERROR_SUCCESS);
    check("shared_type", type, REG_DWORD);
    check("shared_value", actual, number);
    ret = RegLoadAppKeyW(path, &reader, KEY_READ, 0, 0);
    check("shared_read_only_load", ret, ERROR_SUCCESS);
    if (ret) goto done;
    check("shared_read_only_write", RegSetValueExW(reader, L"Shared", 0, REG_DWORD,
          (const BYTE *)&number, sizeof(number)), ERROR_ACCESS_DENIED);
    check("shared_close_first", RegCloseKey(root), ERROR_SUCCESS);
    root = NULL;
    check("shared_close_second", RegCloseKey(second), ERROR_SUCCESS);
    second = NULL;
    actual = 0;
    size = sizeof(actual);
    check("shared_last_reader", RegQueryValueExW(reader, L"Shared", NULL, &type,
          (BYTE *)&actual, &size), ERROR_SUCCESS);
    check("shared_last_value", actual, number);
    check("shared_close_reader", RegCloseKey(reader), ERROR_SUCCESS);
    reader = NULL;

    ret = RegLoadAppKeyW(path, &root, KEY_READ, REG_PROCESS_APPKEY, 0);
    check("lifetime_reload", ret, ERROR_SUCCESS);
    if (ret) goto done;
    actual = 0;
    size = sizeof(actual);
    check("lifetime_persisted_root", RegQueryValueExW(root, L"Shared", NULL, &type,
          (BYTE *)&actual, &size), ERROR_SUCCESS);
    check("lifetime_persisted_root_value", actual, number);
    ret = RegOpenKeyExW(root, L"Fixture\\Child", 0, KEY_READ, &child);
    check("lifetime_reopen_child", ret, ERROR_SUCCESS);
    if (ret) goto done;
    actual = 0;
    size = sizeof(actual);
    check("lifetime_persisted_child", RegQueryValueExW(child, L"Lifetime", NULL, &type,
          (BYTE *)&actual, &size), ERROR_SUCCESS);
    check("lifetime_persisted_child_value", actual, number);
done:
    if (child) check("lifetime_final_child", RegCloseKey(child), ERROR_SUCCESS);
    if (reader) check("lifetime_final_reader", RegCloseKey(reader), ERROR_SUCCESS);
    if (second) check("lifetime_final_second", RegCloseKey(second), ERROR_SUCCESS);
    if (root) check("lifetime_final_root", RegCloseKey(root), ERROR_SUCCESS);
}

#ifdef REGISTRY_HIVE_CODEC
static BOOL write_fixture(const WCHAR *path, const void *data, size_t size)
{
    HANDLE file;
    DWORD written;
    BOOL ret;

    if (size > MAXDWORD) return FALSE;
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ret = WriteFile(file, data, (DWORD)size, &written, NULL) && written == size && FlushFileBuffers(file);
    CloseHandle(file);
    return ret;
}

static void test_journal(const void *data, size_t size, const WCHAR *directory)
{
    WCHAR path[MAX_PATH], log_path[MAX_PATH];
    unsigned char *damaged = NULL;
    void *log = NULL;
    size_t log_size = 0;
    HKEY root = NULL, child = NULL;
    DWORD number, value_size, type;
    unsigned int mode;
    LONG ret;

    swprintf(path, MAX_PATH, L"%ls\\recovery.dat", directory);
    swprintf(log_path, MAX_PATH, L"%ls.LOG1", path);
    ret = reg_hive_log_encode(data, size, 17, &log, &log_size);
    check("journal_encode", ret, 0);
    if (ret) return;
    damaged = malloc(size);
    if (!damaged) { check("journal_allocate", 1, 0); goto done; }
    for (mode = 0; mode < 2; mode++)
    {
        memcpy(damaged, data, size);
        memset(damaged + 4096, 0, size - 4096);
        ret = reg_hive_set_sequence(damaged, size, 18, 17);
        check("journal_dirty_header", ret, 0);
        if (ret) goto done;
        if (mode) damaged[0] ^= 1;
        ret = write_fixture(log_path, log, log_size);
        check("journal_write_log", ret, TRUE);
        if (!ret) goto remove;
        ret = write_fixture(path, damaged, size);
        check("journal_write_main", ret, TRUE);
        if (!ret) goto remove;
        ret = RegLoadAppKeyW(path, &root, KEY_READ, REG_PROCESS_APPKEY, 0);
        check(mode ? "journal_native_bad_header" : "journal_native_torn_body", ret, ERROR_SUCCESS);
        if (ret) goto remove;
        ret = RegOpenKeyExW(root, L"Fixture\\Child", 0, KEY_READ, &child);
        check("journal_native_child", ret, ERROR_SUCCESS);
        if (!ret)
        {
            number = 0;
            value_size = sizeof(number);
            ret = RegQueryValueExW(child, L"Number", NULL, &type, (BYTE *)&number, &value_size);
            check("journal_native_value", ret, ERROR_SUCCESS);
            check("journal_number_value", !ret && type == REG_DWORD && value_size == sizeof(number) &&
                  number == 0x12345678, TRUE);
            check("journal_close_child", RegCloseKey(child), ERROR_SUCCESS);
            child = NULL;
        }
        check("journal_close_root", RegCloseKey(root), ERROR_SUCCESS);
        root = NULL;
remove:
        remove_file(path);
    }
done:
    free(damaged);
    free(log);
}

static void test_codec(const WCHAR *path, const WCHAR *directory)
{
    static const WCHAR text[] = L"application hive fixture";
    static const BYTE binary[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
    WCHAR rewritten[MAX_PATH], value[64];
    struct reg_hive_key *tree = NULL;
    HKEY root = NULL, child = NULL;
    HANDLE input, output;
    LARGE_INTEGER length;
    DWORD size, transferred, number = 0, type;
    unsigned char *data = NULL;
    void *encoded = NULL;
    size_t encoded_size = 0;
    int ret;

    swprintf(rewritten, MAX_PATH, L"%ls\\codec.dat", directory);
    input = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    check("codec_input", input == INVALID_HANDLE_VALUE ? GetLastError() : 0, 0);
    if (input == INVALID_HANDLE_VALUE) return;
    if (!GetFileSizeEx(input, &length) || length.QuadPart <= 0 || length.QuadPart > 32*1024*1024)
    {
        CloseHandle(input);
        check("codec_input_size", 1, 0);
        return;
    }
    size = (DWORD)length.QuadPart;
    data = malloc(size);
    if (!data) { CloseHandle(input); check("codec_allocate", 1, 0); return; }
    ret = ReadFile(input, data, size, &transferred, NULL) && transferred == size;
    CloseHandle(input);
    check("codec_read", ret, TRUE);
    if (!ret) goto done;
    ret = reg_hive_decode(data, size, &tree);
    check("codec_decode", ret, 0);
    if (ret) goto done;
    ret = reg_hive_encode(tree, &encoded, &encoded_size);
    check("codec_encode", ret, 0);
    if (ret || encoded_size > MAXDWORD) goto done;
    test_journal(encoded, encoded_size, directory);
    output = CreateFileW(rewritten, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    check("codec_output", output == INVALID_HANDLE_VALUE ? GetLastError() : 0, 0);
    if (output == INVALID_HANDLE_VALUE) goto done;
    ret = WriteFile(output, encoded, (DWORD)encoded_size, &transferred, NULL) && transferred == encoded_size;
    CloseHandle(output);
    check("codec_write", ret, TRUE);
    if (!ret) goto remove;
    ret = RegLoadAppKeyW(rewritten, &root, KEY_READ, REG_PROCESS_APPKEY, 0);
    check("codec_native_load", ret, ERROR_SUCCESS);
    if (ret) goto remove;
    ret = RegOpenKeyExW(root, L"Fixture\\Child", 0, KEY_READ, &child);
    check("codec_native_subkey", ret, ERROR_SUCCESS);
    if (ret) goto close;
    size = sizeof(number);
    ret = RegQueryValueExW(child, L"Number", NULL, &type, (BYTE *)&number, &size);
    check("codec_native_number", ret, ERROR_SUCCESS);
    check("codec_number_value", !ret && type == REG_DWORD && size == sizeof(number) && number == 0x12345678, TRUE);
    size = sizeof(value);
    ret = RegQueryValueExW(child, L"Text", NULL, &type, (BYTE *)value, &size);
    check("codec_native_text", ret, ERROR_SUCCESS);
    check("codec_text_value", !ret && type == REG_SZ && size == sizeof(text) && !memcmp(value, text, sizeof(text)), TRUE);
    size = sizeof(value);
    ret = RegQueryValueExW(child, L"Binary", NULL, &type, (BYTE *)value, &size);
    check("codec_native_binary", ret, ERROR_SUCCESS);
    check("codec_binary_value", !ret && type == REG_BINARY && size == sizeof(binary) && !memcmp(value, binary, sizeof(binary)), TRUE);
    check("codec_close_child", RegCloseKey(child), ERROR_SUCCESS);
close:
    check("codec_close_root", RegCloseKey(root), ERROR_SUCCESS);
remove:
    remove_file(rewritten);
done:
    reg_hive_free(tree);
    free(encoded);
    free(data);
}
#endif

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

    if (argc == 5 && !lstrcmpW(argv[1], L"--child"))
        return child_access(argv[2], wcstoul(argv[3], NULL, 0), wcstoul(argv[4], NULL, 0));
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
    test_security(root, subkey);
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
    check("second_open", ret, ERROR_SHARING_VIOLATION);
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
        check("snapshot", copy_hive_snapshot(path, argv[2]) ? 0 : GetLastError(), ERROR_SUCCESS);
#ifdef REGISTRY_HIVE_CODEC
    test_codec(path, argv[1]);
#endif

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
    test_lifetime(path);
    test_processes(path);
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
