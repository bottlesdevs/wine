#define COBJMACROS
#include <windows.h>
#include <oleauto.h>
#include <stdio.h>

static HRESULT query(const GUID *guid, const char *stage)
{
    BSTR path = NULL;
    HRESULT hr = QueryPathOfRegTypeLib(guid, 1, 0, 0, &path);
    printf("STAGE=%s QUERY_1_0=%08lx PATH=%ls\n", stage,
            (unsigned long)hr, path ? path : L"(null)");
    SysFreeString(path);
    return hr;
}

int wmain(int argc, WCHAR **argv)
{
    const WCHAR *key = L"TypeLib\\{2D41213F-654B-4308-8A63-EAE2B11E0791}";
    const WCHAR *placeholder = L"TypeLib\\{2D41213F-654B-4308-8A63-EAE2B11E0791}\\1.0";
    const WCHAR *file = L"C:\\soda-typelib-smoke.tlb";
    const WCHAR *assembly = L"SodaTest, Version=1.0.0.0";
    ICreateTypeLib2 *create = NULL;
    ITypeLib *lib = NULL;
    GUID guid;
    HKEY reg;
    HRESULT hr, before, missing, restored;
    BSTR absent_path = NULL;
    LONG status;
    if (argc > 2 || (argc == 2 && !_wfreopen(argv[1], L"w", stdout))) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("POINTER_BITS=%u\n", (unsigned int)(sizeof(void *) * 8));
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 3;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key, 0, KEY_READ, &reg) == ERROR_SUCCESS)
    { RegCloseKey(reg); return 3; }
    CLSIDFromString(L"{2D41213F-654B-4308-8A63-EAE2B11E0791}", &guid);
    hr = CreateTypeLib2(sizeof(void *) == 8 ? SYS_WIN64 : SYS_WIN32, file, &create);
    printf("CREATE=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_SetGuid(create, &guid);
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_SetVersion(create, 1, 1);
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_SetName(create, L"SodaTest");
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_SaveAllChanges(create);
    if (FAILED(hr)) goto done;
    hr = LoadTypeLibEx(file, REGKIND_NONE, &lib);
    if (FAILED(hr)) goto done;
    hr = RegisterTypeLib(lib, (WCHAR *)file, NULL);
    printf("REGISTER_1_1=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    before = query(&guid, "valid-higher-version");
    status = RegCreateKeyExW(HKEY_CLASSES_ROOT, placeholder, 0, NULL, 0,
            KEY_WRITE, NULL, &reg, NULL);
    if (status) { hr = HRESULT_FROM_WIN32(status); goto done; }
    status = RegSetValueExW(reg, L"PrimaryInteropAssemblyName", 0, REG_SZ,
            (const BYTE *)assembly, (lstrlenW(assembly) + 1) * sizeof(WCHAR));
    RegCloseKey(reg);
    if (status) { hr = HRESULT_FROM_WIN32(status); goto done; }
    missing = query(&guid, "metadata-only-exact-version");
    status = RegDeleteKeyW(HKEY_CLASSES_ROOT, placeholder);
    if (status) { hr = HRESULT_FROM_WIN32(status); goto done; }
    restored = query(&guid, "placeholder-removed");
    hr = SUCCEEDED(before) && missing == S_OK &&
            SUCCEEDED(restored) ? S_OK : E_FAIL;
    printf("CANDIDATE_SELECTION_PASS=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    hr = QueryPathOfRegTypeLib(&guid, 2, 0, 0, &absent_path);
    printf("WRONG_MAJOR=%08lx\n", (unsigned long)hr);
    SysFreeString(absent_path); absent_path = NULL;
    if (hr != TYPE_E_LIBNOTREGISTERED) { hr = E_FAIL; goto done; }
    hr = QueryPathOfRegTypeLib(&guid, 1, 2, 0, &absent_path);
    printf("NEWER_MINOR=%08lx\n", (unsigned long)hr);
    SysFreeString(absent_path); absent_path = NULL;
    if (hr != TYPE_E_LIBNOTREGISTERED) { hr = E_FAIL; goto done; }
    hr = ICreateTypeLib2_SetVersion(create, 1, 0);
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_SaveAllChanges(create);
    if (FAILED(hr)) goto done;
    ITypeLib_Release(lib); lib = NULL;
    hr = LoadTypeLibEx(file, REGKIND_NONE, &lib);
    if (FAILED(hr)) goto done;
    hr = RegisterTypeLib(lib, (WCHAR *)file, NULL);
    if (FAILED(hr)) goto done;
    ITypeLib_Release(lib); lib = NULL;
    hr = LoadRegTypeLib(&guid, 1, 0, 0, &lib);
    printf("REGISTERED_EXACT_LOAD=%08lx\n", (unsigned long)hr);
    if (SUCCEEDED(hr))
    {
        TLIBATTR *attr;
        hr = ITypeLib_GetLibAttr(lib, &attr);
        if (SUCCEEDED(hr))
        {
            printf("REGISTERED_EXACT_VERSION=%u.%u\n", attr->wMajorVerNum, attr->wMinorVerNum);
            if (attr->wMajorVerNum != 1 || attr->wMinorVerNum != 0) hr = E_FAIL;
            ITypeLib_ReleaseTLibAttr(lib, attr);
        }
    }
done:
    if (lib) ITypeLib_Release(lib);
    if (create) ICreateTypeLib2_Release(create);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, key);
    DeleteFileW(file);
    CoUninitialize();
    printf("RESULT=%08lx\n", (unsigned long)hr);
    return FAILED(hr) ? 1 : 0;
}
