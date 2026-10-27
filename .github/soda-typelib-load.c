#define COBJMACROS
#include <windows.h>
#include <oleauto.h>
#include <stdio.h>
#include <wchar.h>

static HRESULT create_library(const WCHAR *path, UINT count)
{
    ICreateTypeLib2 *library = NULL;
    ICreateTypeInfo *info = NULL;
    VARIANT value;
    VARDESC desc = {0};
    WCHAR name[64], doc[64];
    HRESULT hr;
    UINT i;

    hr = CreateTypeLib2(sizeof(void *) == 8 ? SYS_WIN64 : SYS_WIN32, path, &library);
    if (FAILED(hr)) return hr;
    hr = ICreateTypeLib2_SetName(library, L"SodaOwnedTypeLibrary");
    if (FAILED(hr)) goto done;
    hr = ICreateTypeLib2_CreateTypeInfo(library, L"SodaOwnedValues", TKIND_ENUM, &info);
    if (FAILED(hr)) goto done;
    VariantInit(&value);
    V_VT(&value) = VT_I4;
    desc.varkind = VAR_CONST;
    desc.elemdescVar.tdesc.vt = VT_I4;
    desc.lpvarValue = &value;
    for (i = 0; i < count; i++)
    {
        desc.memid = 1000 + i;
        V_I4(&value) = i * 3 + 1;
        hr = ICreateTypeInfo_AddVarDesc(info, i, &desc);
        if (FAILED(hr)) goto done;
        swprintf(name, 64, L"OwnedValue%05u", i);
        swprintf(doc, 64, L"Owned documentation %05u", i);
        hr = ICreateTypeInfo_SetVarName(info, i, name);
        if (FAILED(hr)) goto done;
        hr = ICreateTypeInfo_SetVarDocString(info, i, doc);
        if (FAILED(hr)) goto done;
    }
    hr = ICreateTypeInfo_LayOut(info);
    if (SUCCEEDED(hr)) hr = ICreateTypeLib2_SaveAllChanges(library);
done:
    if (info) ICreateTypeInfo_Release(info);
    ICreateTypeLib2_Release(library);
    return hr;
}

static HRESULT measure_library(const WCHAR *path, UINT count)
{
    ITypeLib *library = NULL;
    ITypeInfo *info = NULL;
    TYPEATTR *attr = NULL;
    LARGE_INTEGER before, after, frequency;
    HRESULT hr;
    UINT i, checked = 0;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&before);
    hr = LoadTypeLibEx(path, REGKIND_NONE, &library);
    QueryPerformanceCounter(&after);
    printf("LOAD count=%u elapsed_us=%.3f hr=%08lx\n", count,
            (after.QuadPart - before.QuadPart) * 1000000.0 / frequency.QuadPart,
            (unsigned long)hr);
    if (FAILED(hr)) return hr;
    if (ITypeLib_GetTypeInfoCount(library) != 1) { hr = E_FAIL; goto done; }
    hr = ITypeLib_GetTypeInfo(library, 0, &info);
    if (FAILED(hr)) goto done;
    hr = ITypeInfo_GetTypeAttr(info, &attr);
    if (FAILED(hr)) goto done;
    if (attr->typekind != TKIND_ENUM || attr->cVars != count) { hr = E_FAIL; goto done; }
    for (i = 0; i < count; i++)
    {
        WCHAR expected_name[64], expected_doc[64];
        BSTR name = NULL, doc = NULL;
        VARDESC *desc;
        hr = ITypeInfo_GetVarDesc(info, i, &desc);
        if (FAILED(hr)) goto done;
        if (desc->memid != (MEMBERID)(1000 + i) || desc->varkind != VAR_CONST ||
                V_VT(desc->lpvarValue) != VT_I4 || V_I4(desc->lpvarValue) != (LONG)(i * 3 + 1))
            hr = E_FAIL;
        ITypeInfo_ReleaseVarDesc(info, desc);
        if (FAILED(hr)) goto done;
        hr = ITypeInfo_GetDocumentation(info, 1000 + i, &name, &doc, NULL, NULL);
        swprintf(expected_name, 64, L"OwnedValue%05u", i);
        swprintf(expected_doc, 64, L"Owned documentation %05u", i);
        if (SUCCEEDED(hr) && (!name || !doc || wcscmp(name, expected_name) || wcscmp(doc, expected_doc))) hr = E_FAIL;
        SysFreeString(name);
        SysFreeString(doc);
        if (FAILED(hr)) goto done;
        checked++;
    }
done:
    printf("CHECK count=%u checked=%u hr=%08lx\n", count, checked, (unsigned long)hr);
    if (attr) ITypeInfo_ReleaseTypeAttr(info, attr);
    if (info) ITypeInfo_Release(info);
    ITypeLib_Release(library);
    return hr;
}

int wmain(int argc, WCHAR **argv)
{
    WCHAR *end;
    unsigned long count;
    HRESULT hr;
    if (argc != 4) return 2;
    count = wcstoul(argv[2], &end, 10);
    if (*end || !count || count > 32768) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 3;
    if (!wcscmp(argv[1], L"make")) hr = create_library(argv[3], count);
    else if (!wcscmp(argv[1], L"load")) hr = measure_library(argv[3], count);
    else hr = E_INVALIDARG;
    CoUninitialize();
    printf("RESULT=%08lx POINTER_BITS=%u\n", (unsigned long)hr, (unsigned int)(sizeof(void *) * 8));
    return FAILED(hr) ? 1 : 0;
}
