#define COBJMACROS
#include <windows.h>
#include <oleauto.h>
#include <stdio.h>
#include <wchar.h>

static const GUID base_id = {0x6a7b1c94,0x402e,0x4f8c,{0x86,0xd0,0x14,0x73,0x2a,0x8f,0x57,0x1b}};
static const GUID alias_id = {0x7af3e4a5,0x8063,0x4f1c,{0x83,0x2d,0x96,0x70,0x2c,0x5e,0x31,0x4a}};
static const GUID enum_id = {0xc2510e8f,0x535b,0x4f36,{0xa8,0x52,0x5c,0x49,0xe2,0x62,0x97,0xd3}};

static HRESULT make_base(const WCHAR *path, SYSKIND kind, LONG answer)
{
    ICreateTypeLib2 *library = NULL;
    ICreateTypeInfo *info = NULL;
    VARIANT value;
    VARDESC desc = {0};
    HRESULT hr;
#define CHECK(call) do { hr = (call); if (FAILED(hr)) goto done; } while (0)
    CHECK(CreateTypeLib2(kind, path, &library));
    CHECK(ICreateTypeLib2_SetGuid(library, &base_id));
    CHECK(ICreateTypeLib2_SetVersion(library, 1, 0));
    CHECK(ICreateTypeLib2_SetLcid(library, 0));
    CHECK(ICreateTypeLib2_SetName(library, L"SodaOwnedImportedLibrary"));
    CHECK(ICreateTypeLib2_CreateTypeInfo(library, L"SodaOwnedEnum", TKIND_ENUM, &info));
    CHECK(ICreateTypeInfo_SetGuid(info, &enum_id));
    VariantInit(&value);
    V_VT(&value) = VT_I4;
    V_I4(&value) = answer;
    desc.memid = 42;
    desc.varkind = VAR_CONST;
    desc.elemdescVar.tdesc.vt = VT_I4;
    desc.lpvarValue = &value;
    CHECK(ICreateTypeInfo_AddVarDesc(info, 0, &desc));
    CHECK(ICreateTypeInfo_SetVarName(info, 0, L"OwnedAnswer"));
    CHECK(ICreateTypeInfo_LayOut(info));
    CHECK(ICreateTypeLib2_SaveAllChanges(library));
done:
    if (info) ICreateTypeInfo_Release(info);
    if (library) ICreateTypeLib2_Release(library);
    return hr;
#undef CHECK
}

static HRESULT make_alias(const WCHAR *path, SYSKIND kind, ITypeInfo *base)
{
    ICreateTypeLib2 *library = NULL;
    ICreateTypeInfo *info = NULL;
    TYPEDESC desc = {0};
    HRESULT hr;
#define CHECK(call) do { hr = (call); if (FAILED(hr)) goto done; } while (0)
    CHECK(CreateTypeLib2(kind, path, &library));
    CHECK(ICreateTypeLib2_SetGuid(library, &alias_id));
    CHECK(ICreateTypeLib2_SetVersion(library, 1, 0));
    CHECK(ICreateTypeLib2_SetLcid(library, 0));
    CHECK(ICreateTypeLib2_SetName(library, L"SodaOwnedImportingLibrary"));
    CHECK(ICreateTypeLib2_CreateTypeInfo(library, L"SodaOwnedAlias", TKIND_ALIAS, &info));
    desc.vt = VT_USERDEFINED;
    CHECK(ICreateTypeInfo_AddRefTypeInfo(info, base, &desc.hreftype));
    CHECK(ICreateTypeInfo_SetTypeDescAlias(info, &desc));
    CHECK(ICreateTypeInfo_LayOut(info));
    CHECK(ICreateTypeLib2_SaveAllChanges(library));
done:
    if (info) ICreateTypeInfo_Release(info);
    if (library) ICreateTypeLib2_Release(library);
    return hr;
#undef CHECK
}

static HRESULT prepare(const WCHAR *directory, SYSKIND base_kind, SYSKIND alias_kind, BOOL both)
{
    WCHAR original[MAX_PATH], relocated[MAX_PATH], alias[MAX_PATH], other[MAX_PATH];
    ITypeLib *library = NULL;
    ITypeInfo *info = NULL;
    HRESULT hr;

    if (wcslen(directory) > MAX_PATH - 40) return E_INVALIDARG;
    swprintf(original, MAX_PATH, L"%ls\\base-original.tlb", directory);
    swprintf(relocated, MAX_PATH, L"%ls\\base-registered.tlb", directory);
    swprintf(alias, MAX_PATH, L"%ls\\importing.tlb", directory);
    swprintf(other, MAX_PATH, L"%ls\\other-platform.tlb", directory);
    hr = make_base(original, base_kind, 42);
    if (SUCCEEDED(hr)) hr = LoadTypeLibEx(original, REGKIND_REGISTER, &library);
    if (SUCCEEDED(hr)) hr = ITypeLib_GetTypeInfo(library, 0, &info);
    if (SUCCEEDED(hr)) hr = make_alias(alias, alias_kind, info);
    if (info) ITypeInfo_Release(info);
    if (library) ITypeLib_Release(library);
    library = NULL;
    if (SUCCEEDED(hr) && !MoveFileW(original, relocated)) hr = HRESULT_FROM_WIN32(GetLastError());
    if (SUCCEEDED(hr)) hr = LoadTypeLibEx(relocated, REGKIND_REGISTER, &library);
    if (library) ITypeLib_Release(library);
    library = NULL;
    if (both && SUCCEEDED(hr))
    {
        hr = make_base(other, base_kind == SYS_WIN32 ? SYS_WIN64 : SYS_WIN32, 84);
        if (SUCCEEDED(hr)) hr = LoadTypeLibEx(other, REGKIND_REGISTER, &library);
        if (library) ITypeLib_Release(library);
    }
    printf("PREPARE base_kind=%u alias_kind=%u both=%u hr=%08lx\n",
            (unsigned int)base_kind, (unsigned int)alias_kind, (unsigned int)both, (unsigned long)hr);
    return hr;
}

static HRESULT probe(const WCHAR *path, BOOL both)
{
    ITypeLib *library = NULL;
    ITypeInfo *info = NULL, *referenced = NULL;
    TYPEATTR *attr = NULL;
    VARDESC *value = NULL;
    HREFTYPE reference = 0;
    HRESULT hr, lookup = E_UNEXPECTED;
    BSTR registered = NULL;

    hr = QueryPathOfRegTypeLib(&base_id, 1, 0, 0, &registered);
    printf("PUBLIC_REGISTERED_PATH hr=%08lx path=%ls\n", (unsigned long)hr, registered ? registered : L"");
    SysFreeString(registered);
    hr = LoadTypeLibEx(path, REGKIND_NONE, &library);
    if (SUCCEEDED(hr)) hr = ITypeLib_GetTypeInfo(library, 0, &info);
    if (SUCCEEDED(hr)) hr = ITypeInfo_GetTypeAttr(info, &attr);
    if (SUCCEEDED(hr))
    {
        if (attr->typekind != TKIND_ALIAS || attr->tdescAlias.vt != VT_USERDEFINED) hr = E_FAIL;
        reference = attr->tdescAlias.hreftype;
        ITypeInfo_ReleaseTypeAttr(info, attr);
        attr = NULL;
    }
    if (SUCCEEDED(hr)) hr = lookup = ITypeInfo_GetRefTypeInfo(info, reference, &referenced);
    if (SUCCEEDED(hr)) hr = ITypeInfo_GetTypeAttr(referenced, &attr);
    if (SUCCEEDED(hr))
    {
        if (attr->typekind != TKIND_ENUM || attr->cVars != 1 || !IsEqualGUID(&attr->guid, &enum_id)) hr = E_FAIL;
        ITypeInfo_ReleaseTypeAttr(referenced, attr);
        attr = NULL;
    }
    if (SUCCEEDED(hr)) hr = ITypeInfo_GetVarDesc(referenced, 0, &value);
    if (SUCCEEDED(hr))
    {
        if (value->memid != 42 || value->varkind != VAR_CONST ||
                V_VT(value->lpvarValue) != VT_I4) hr = E_FAIL;
        else
        {
            LONG answer = V_I4(value->lpvarValue);
            printf("RESOLVED_CONSTANT value=%ld\n", answer);
            if (answer != 42 && (!both || answer != 84)) hr = E_FAIL;
        }
        ITypeInfo_ReleaseVarDesc(referenced, value);
    }
    if (referenced) ITypeInfo_Release(referenced);
    if (info) ITypeInfo_Release(info);
    if (library) ITypeLib_Release(library);
    printf("LOOKUP hr=%08lx RESULT=%08lx POINTER_BITS=%u\n", (unsigned long)lookup,
            (unsigned long)hr, (unsigned int)(sizeof(void *) * 8));
    return hr;
}

int wmain(int argc, WCHAR **argv)
{
    HRESULT hr;

    if (argc < 2) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 3;
    if ((!wcscmp(argv[1], L"make") || !wcscmp(argv[1], L"make-both")) && argc == 5 &&
            (!wcscmp(argv[2], L"32") || !wcscmp(argv[2], L"64")) &&
            (!wcscmp(argv[3], L"32") || !wcscmp(argv[3], L"64")))
        hr = prepare(argv[4], wcscmp(argv[2], L"32") ? SYS_WIN64 : SYS_WIN32,
                wcscmp(argv[3], L"32") ? SYS_WIN64 : SYS_WIN32, !wcscmp(argv[1], L"make-both"));
    else if ((!wcscmp(argv[1], L"probe") || !wcscmp(argv[1], L"probe-both")) && argc == 3)
        hr = probe(argv[2], !wcscmp(argv[1], L"probe-both"));
    else if (!wcscmp(argv[1], L"cleanup") && argc == 2)
    {
        HRESULT win32 = UnRegisterTypeLib(&base_id, 1, 0, 0, SYS_WIN32);
        HRESULT win64 = UnRegisterTypeLib(&base_id, 1, 0, 0, SYS_WIN64);
        printf("CLEANUP win32=%08lx win64=%08lx\n", (unsigned long)win32, (unsigned long)win64);
        hr = SUCCEEDED(win32) || SUCCEEDED(win64) ? S_OK : E_FAIL;
    }
    else hr = E_INVALIDARG;
    CoUninitialize();
    return FAILED(hr) ? 1 : 0;
}
