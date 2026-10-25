#include <windows.h>
#include <msi.h>
#include <stdio.h>
#include <string.h>

static const WCHAR configuration[] = L"Software\\Microsoft\\Office\\ClickToRun\\Configuration";
static const WCHAR component[] = L"{79F2A851-F5DE-4C47-8192-9340E7145068}";
static const WCHAR product[] = L"{79F2A852-F5DE-4C47-8192-9340E7145068}";
static const WCHAR unknown[] = L"{79F2A853-F5DE-4C47-8192-9340E7145068}";
static WCHAR manifest[MAX_PATH];
static unsigned int checks, failures;

static void check(BOOL value, const char *name)
{
    ++checks;
    if (!value)
    {
        ++failures;
        printf("FAIL %s\n", name);
    }
}

static void test_manifest(const char *name, const WCHAR *body, const WCHAR *id, BOOL present)
{
    WCHAR text[4096], result[39];
    char narrow_id[39], narrow_result[39], narrow_product[39];
    DWORD written, bytes;
    HANDLE file;
    UINT status;

    swprintf(text, ARRAYSIZE(text), L"\xfeff<Package ProductCode=\"%ls\">%ls</Package>", product, body);
    bytes = lstrlenW(text) * sizeof(WCHAR);
    file = CreateFileW(manifest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "manifest create");
    if (file == INVALID_HANDLE_VALUE) return;
    check(WriteFile(file, text, bytes, &written, NULL) && written == bytes, "manifest write");
    CloseHandle(file);

    lstrcpyW(result, L"unchanged");
    status = MsiGetProductCodeW(id, result);
    printf("%s unicode=%u\n", name, status);
    check(status == (present ? ERROR_SUCCESS : ERROR_UNKNOWN_COMPONENT), name);
    check(!lstrcmpW(result, present ? product : L"unchanged"), "unicode result");

    WideCharToMultiByte(CP_ACP, 0, id, -1, narrow_id, sizeof(narrow_id), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, product, -1, narrow_product, sizeof(narrow_product), NULL, NULL);
    strcpy(narrow_result, "unchanged");
    status = MsiGetProductCodeA(narrow_id, narrow_result);
    printf("%s ansi=%u\n", name, status);
    check(status == (present ? ERROR_SUCCESS : ERROR_UNKNOWN_COMPONENT), name);
    check(!strcmp(narrow_result, present ? narrow_product : "unchanged"), "ansi result");
}

static void test_paths(const WCHAR *root)
{
    static const WCHAR body[] =
        L"<Components><Component ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\" "
        L"KeyPath=\"%SFT_PROGRAM_FILES_X64%\\Microsoft Office\\Office16\\fixture.dat\"/>"
        L"</Components>";
    INSTALLSTATE (WINAPI *get_path)(LPCWSTR, LPCWSTR, LPCWSTR, MSIINSTALLCONTEXT, LPWSTR, LPDWORD);
    WCHAR path[MAX_PATH], expected[MAX_PATH];
    char narrow_path[MAX_PATH], narrow_expected[MAX_PATH];
    INSTALLSTATE state;
    DWORD size;
    HANDLE file;

    get_path = (void *)GetProcAddress(GetModuleHandleW(L"msi.dll"), "MsiGetComponentPathExW");
    check(!!get_path, "component path export");
    if (!get_path) return;
    swprintf(expected, ARRAYSIZE(expected), L"%ls\\root\\Office16\\fixture.dat", root);
    file = CreateFileW(expected, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "component file create");
    if (file == INVALID_HANDLE_VALUE) return;
    CloseHandle(file);
    test_manifest("file-path", body, component, TRUE);
    check(MsiGetProductCodeW(component, NULL) == ERROR_INVALID_PARAMETER, "missing product output");

    path[0] = 0;
    size = ARRAYSIZE(path);
    state = get_path(product, component, NULL, MSIINSTALLCONTEXT_MACHINE, path, &size);
    check(state == INSTALLSTATE_LOCAL, "machine file state");
    check(!lstrcmpW(path, expected) && size == (DWORD)lstrlenW(expected), "machine file path");
    path[0] = 0;
    size = ARRAYSIZE(path);
    state = get_path(product, component, L"S-1-1-0", MSIINSTALLCONTEXT_ALL, path, &size);
    check(state == INSTALLSTATE_LOCAL && !lstrcmpW(path, expected), "all-context file path");

    path[0] = 0;
    size = ARRAYSIZE(path);
    state = MsiGetComponentPathW(product, component, path, &size);
    check(state == INSTALLSTATE_LOCAL && !lstrcmpW(path, expected), "legacy unicode file path");
    WideCharToMultiByte(CP_ACP, 0, expected, -1, narrow_expected, sizeof(narrow_expected), NULL, NULL);
    size = sizeof(narrow_path);
    state = MsiGetComponentPathA("{79F2A852-F5DE-4C47-8192-9340E7145068}",
                               "{79F2A851-F5DE-4C47-8192-9340E7145068}", narrow_path, &size);
    check(state == INSTALLSTATE_LOCAL && !strcmp(narrow_path, narrow_expected), "legacy ansi file path");

    lstrcpyW(path, L"unchanged");
    size = ARRAYSIZE(path);
    state = get_path(unknown, component, NULL, MSIINSTALLCONTEXT_MACHINE, path, &size);
    check(state == INSTALLSTATE_UNKNOWN && !lstrcmpW(path, L"unchanged"), "product isolation");
    state = get_path(product, component, NULL, MSIINSTALLCONTEXT_USERUNMANAGED, path, &size);
    check(state == INSTALLSTATE_UNKNOWN && !lstrcmpW(path, L"unchanged"), "user context isolation");
    state = get_path(product, component, L"S-1-1-0", MSIINSTALLCONTEXT_MACHINE, path, &size);
    check(state == INSTALLSTATE_INVALIDARG, "machine SID argument");

    size = 1;
    state = get_path(product, component, NULL, MSIINSTALLCONTEXT_MACHINE, path, &size);
    check(state == INSTALLSTATE_MOREDATA && size == (DWORD)lstrlenW(expected), "short path buffer");
    check(DeleteFileW(expected), "component file cleanup");
    path[0] = 0;
    size = ARRAYSIZE(path);
    state = get_path(product, component, NULL, MSIINSTALLCONTEXT_MACHINE, path, &size);
    check(state == INSTALLSTATE_ABSENT && !lstrcmpW(path, expected), "missing component file");
}

static void test_published(const WCHAR *root)
{
    static const WCHAR published_id[] = L"{79F2A855-F5DE-4C47-8192-9340E7145068}";
    static const WCHAR body[] =
        L"<Components><Component ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\" "
        L"KeyPath=\"%SFT_PROGRAM_FILES_X64%\\Microsoft Office\\Office16\\fixture.dat\">"
        L"<PublishComponent PublishComponentId=\"{79F2A855-F5DE-4C47-8192-9340E7145068}\" "
        L"Qualifier=\"fixture.dat\" AppData=\"ProductFiles\"/></Component></Components>";
    WCHAR path[MAX_PATH], expected[MAX_PATH], qualifier[64] = {0}, data[64] = {0};
    char narrow_qualifier[64], narrow_data[64];
    DWORD size, qualifier_size, data_size;
    HANDLE file;
    UINT result;

    swprintf(expected, ARRAYSIZE(expected), L"%ls\\root\\Office16\\fixture.dat", root);
    file = CreateFileW(expected, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "published file create");
    if (file == INVALID_HANDLE_VALUE) return;
    CloseHandle(file);
    test_manifest("published-group", body, component, TRUE);

    qualifier_size = ARRAYSIZE(qualifier);
    data_size = ARRAYSIZE(data);
    result = MsiEnumComponentQualifiersW(published_id, 0, qualifier, &qualifier_size, data, &data_size);
    check(result == ERROR_SUCCESS, "published enumeration");
    check(!lstrcmpW(qualifier, L"fixture.dat") && qualifier_size == 11, "published qualifier");
    check(!lstrcmpW(data, L"ProductFiles") && data_size == 12, "published application data");
    qualifier_size = sizeof(narrow_qualifier);
    data_size = sizeof(narrow_data);
    result = MsiEnumComponentQualifiersA("{79F2A855-F5DE-4C47-8192-9340E7145068}", 0,
                                       narrow_qualifier, &qualifier_size, narrow_data, &data_size);
    check(result == ERROR_SUCCESS && !strcmp(narrow_qualifier, "fixture.dat") &&
          !strcmp(narrow_data, "ProductFiles"), "ansi published enumeration");
    qualifier_size = ARRAYSIZE(qualifier);
    result = MsiEnumComponentQualifiersW(published_id, 0, qualifier, &qualifier_size, NULL, NULL);
    check(result == ERROR_SUCCESS && !lstrcmpW(qualifier, L"fixture.dat"), "optional application data");
    result = MsiEnumComponentQualifiersW(published_id, 1, NULL, NULL, NULL, NULL);
    check(result == ERROR_NO_MORE_ITEMS, "published enumeration end");
    qualifier_size = 1;
    data_size = ARRAYSIZE(data);
    result = MsiEnumComponentQualifiersW(published_id, 0, qualifier, &qualifier_size, data, &data_size);
    check(result == ERROR_MORE_DATA && qualifier_size == 11 && !lstrcmpW(data, L"ProductFiles"),
          "short qualifier buffer");

    path[0] = 0;
    size = ARRAYSIZE(path);
    result = MsiProvideQualifiedComponentW(published_id, L"fixture.dat", INSTALLMODE_NODETECTION, path, &size);
    check(result == ERROR_SUCCESS && !lstrcmpW(path, expected), "qualified component file");
    lstrcpyW(path, L"unchanged");
    size = ARRAYSIZE(path);
    result = MsiProvideQualifiedComponentExW(published_id, L"fixture.dat", INSTALLMODE_NODETECTION,
                                            unknown, 0, 0, path, &size);
    check(result != ERROR_SUCCESS && !lstrcmpW(path, L"unchanged"), "qualified product isolation");
    check(DeleteFileW(expected), "published file cleanup");
    size = ARRAYSIZE(path);
    result = MsiProvideQualifiedComponentW(published_id, L"fixture.dat", INSTALLMODE_NODETECTION, path, &size);
    check(result != ERROR_SUCCESS, "missing qualified file");
}

int wmain(int argc, WCHAR **argv)
{
    static const WCHAR plain[] =
        L"<Components><Component ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\" "
        L"KeyPath=\"%SFT_PROGRAM_FILES_X64%\\Example\\data.dll\"></Component></Components>";
    static const WCHAR published[] =
        L"<Components><Component ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\" "
        L"KeyPath=\"00:\\Example\\Value\"><PublishComponent "
        L"PublishComponentId=\"{79F2A854-F5DE-4C47-8192-9340E7145068}\" "
        L"Qualifier=\"data.dll\"/></Component></Components>";
    static const WCHAR lower[] =
        L"<components><component componentid=\"{79f2a851-f5de-4c47-8192-9340e7145068}\" "
        L"keypath=\"data.dll\"/></components>";
    static const WCHAR reference[] =
        L"<Feature><Component ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\"/>"
        L"</Feature>";
    static const WCHAR misleading[] =
        L"<Component OtherComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\" "
        L"KeyPath=\"data.dll\"/>";
    static const WCHAR legacy[] =
        L"<PublishComponentList><PublishComponent "
        L"ComponentId=\"{79F2A851-F5DE-4C47-8192-9340E7145068}\"/></PublishComponentList>";
    HKEY key;
    DWORD disposition;
    LONG status;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2 || (unsigned int)lstrlenW(argv[1]) + 70 >= ARRAYSIZE(manifest)) return 2;
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, configuration, 0, NULL, 0,
                            KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &key, &disposition);
    if (status || disposition != REG_CREATED_NEW_KEY)
    {
        if (!status) RegCloseKey(key);
        printf("Refusing to replace an existing test configuration\n");
        return 3;
    }
    status = RegSetValueExW(key, L"InstallationPath", 0, REG_SZ, (BYTE *)argv[1],
                            (lstrlenW(argv[1]) + 1) * sizeof(WCHAR));
    RegCloseKey(key);
    if (status) return 4;
    swprintf(manifest, ARRAYSIZE(manifest), L"%ls\\root\\Integration\\C2RManifest.fixture.xml", argv[1]);

    test_manifest("plain", plain, component, TRUE);
    test_manifest("published", published, component, TRUE);
    test_manifest("lowercase", lower, component, TRUE);
    test_manifest("reference-only", reference, component, FALSE);
    test_manifest("attribute-boundary", misleading, component, FALSE);
    test_manifest("unknown", plain, unknown, FALSE);
    test_manifest("legacy", legacy, component, TRUE);
    test_paths(argv[1]);
    test_published(argv[1]);

    check(DeleteFileW(manifest), "manifest cleanup");
    check(RegDeleteKeyExW(HKEY_LOCAL_MACHINE, configuration, KEY_WOW64_64KEY, 0) == ERROR_SUCCESS,
          "configuration cleanup");
    printf("MSI_COMPONENT_RESULT checks=%u failures=%u\n", checks, failures);
    return failures != 0;
}
