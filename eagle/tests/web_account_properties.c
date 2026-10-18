#define INITGUID
#include "private.h"
#include <stdio.h>
#define CHECK(call) do { HRESULT check_hr = (call); if (FAILED(check_hr)) { fprintf(stderr, "line=%u hr=%08lx\n", __LINE__, check_hr); return __LINE__; } } while (0)
static HSTRING string(const WCHAR *s)
{
    HSTRING value = NULL;
    WindowsCreateString(s, wcslen(s), &value);
    return value;
}
int main(int argc, char **argv)
{
    static const struct { const WCHAR *authority; const char *id; } cases[] = {
        {L"consumers", "00000000-0000-0000-1234-56789abcdef0"},
        {L"consumers", "00000000-0000-0000-ABCD-EF0123456789"},
        {L"9188040d-6c67-4c5b-b112-36a304b66dad", "00000000-0000-0000-1234-56789abcdef0"},
        {L"organizations", "00000000-0000-0000-1234-56789abcdef0"},
        {L"common", "00000000-0000-0000-1234-56789abcdef0"},
        {L"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-1234-56789abcdef0"},
        {L"consumers", "00000000-0000-0000-1234-56789abcdeg0"},
        {L"consumers", "00000000-0000-0000-1234x56789abcdef0"},
        {L"consumers", "00000000-0000-0001-1234-56789abcdef0"},
        {L"consumers", "00000000-0000-0000-1234-56789abcdef"},
        {L"consumers", "fixture-account-id"}
    };
    unsigned int i;
    FILE *output;
    if (argc != 2 || !(output = fopen(argv[1], "w"))) return 1;
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        BYTE buffer[256];
        BYTE *cursor = buffer;
        UINT32 one = 1, size = strlen(cases[i].id), count;
        const char *user = "fixture-user@example.invalid";
        struct identity_reply reply = {0};
        IWebAccountProvider *provider;
        IFindAllAccountsResult *result;
        IVectorView_WebAccount *accounts;
        IWebAccount *account;
        IWebAccount2 *account2;
        IMapView_HSTRING_HSTRING *properties;
        HSTRING id = string(L"https://login.microsoft.com"), display = string(L"Microsoft"), authority = string(cases[i].authority);
        HSTRING key = string(L"SafeCustomerId"), value = NULL;
        HRESULT hr;
        char cid[64];
        int length;
        memcpy(cursor, &one, 4);cursor += 4;
        memcpy(cursor, &size, 4);cursor += 4;
        memcpy(cursor, cases[i].id, size);cursor += size;
        size = strlen(user);memcpy(cursor, &size, 4);cursor += 4;
        memcpy(cursor, user, size);cursor += size;
        reply.accounts = buffer;reply.accounts_size = cursor - buffer;
        CHECK(web_account_provider_create(id, display, authority, FALSE, &provider));
        CHECK(web_accounts_result_create(provider, &reply, &result));
        CHECK(IFindAllAccountsResult_get_Accounts(result, &accounts));
        IFindAllAccountsResult_Release(result);
        IWebAccountProvider_Release(provider);
        CHECK(IVectorView_WebAccount_get_Size(accounts, &count));
        if (count != 1) return 2;
        CHECK(IVectorView_WebAccount_GetAt(accounts, 0, &account));
        IVectorView_WebAccount_Release(accounts);
        CHECK(IWebAccount_QueryInterface(account, &IID_IWebAccount2, (void **)&account2));
        CHECK(IWebAccount2_get_Properties(account2, &properties));
        IWebAccount2_Release(account2);IWebAccount_Release(account);
        hr = IMapView_HSTRING_HSTRING_Lookup(properties, key, &value);
        length = WideCharToMultiByte(CP_UTF8, 0, WindowsGetStringRawBuffer(value, NULL), WindowsGetStringLen(value), cid, sizeof(cid)-1, NULL, NULL);
        cid[length] = 0;fprintf(output, "%u %08lx %s\n", i, hr, cid);
        IMapView_HSTRING_HSTRING_Release(properties);
        WindowsDeleteString(id);WindowsDeleteString(display);WindowsDeleteString(authority);
        WindowsDeleteString(key);WindowsDeleteString(value);
    }
    fclose(output);
    return 0;
}
