#define INITGUID
#define COBJMACROS
#include <windows.h>
#include <winstring.h>
#include <activation.h>
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include <windows.foundation.h>
#define WIDL_using_Windows_Security_Credentials
#include <windows.security.credentials.h>
#define WIDL_using_Windows_Security_Authentication_Web_Core
#include <windows.security.authentication.web.core.h>
#include <roapi.h>
#include <stdio.h>
#include <string.h>

static HRESULT wait_result(IUnknown *value)
{
    IAsyncInfo *info;
    AsyncStatus status = Started;
    unsigned i;
    HRESULT hr = IUnknown_QueryInterface(value, &IID_IAsyncInfo, (void **)&info);
    if (FAILED(hr)) return hr;
    for (i = 0; i < 1000 && status == Started; i++)
    {
        hr = IAsyncInfo_get_Status(info, &status);
        if (FAILED(hr)) break;
        if (status == Started) Sleep(10);
    }
    if (SUCCEEDED(hr) && status != Completed) hr = E_UNEXPECTED;
    IAsyncInfo_Release(info);
    return hr;
}
#define CHECK(call) do { HRESULT check_result = (call); if (FAILED(check_result)) { fprintf(stderr, "line=%u hr=%08lx\n", __LINE__, check_result); return __LINE__; } } while (0)
int main(int argc, char **argv)
{
    static const WCHAR manager_name[] = L"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
    HMODULE module;
    HRESULT (WINAPI *get_factory)(HSTRING, IActivationFactory **);
    IActivationFactory *factory;
    IWebAuthenticationCoreManagerStatics *manager;
    IWebAuthenticationCoreManagerStatics4 *manager4;
    IAsyncOperation_WebAccountProvider *provider_operation;
    IAsyncOperation_FindAllAccountsResult *operation;
    IWebAccountProvider *provider;
    IFindAllAccountsResult *result;
    IVectorView_WebAccount *accounts;
    IWebProviderError *error;
    HSTRING name, provider_id, authority, client_id;
    FindAllWebAccountsStatus status;
    UINT32 count = 0, error_code = 0;
    BOOL token, interactive, record;
    FILE *file;
    if (argc != 2 && (argc != 3 || (strcmp(argv[2], "invalid") && strcmp(argv[2], "silent") && strcmp(argv[2], "interactive") && strcmp(argv[2], "record") && strcmp(argv[2], "refresh") && strcmp(argv[2], "refresh-interactive")))) return 1;
    record = argc == 3 && !strcmp(argv[2], "record");
    token = argc == 3 && (!strcmp(argv[2], "silent") || !strcmp(argv[2], "interactive") || !strcmp(argv[2], "refresh") || !strcmp(argv[2], "refresh-interactive"));
    interactive = token && (!strcmp(argv[2], "interactive") || !strcmp(argv[2], "refresh-interactive"));
    CHECK(RoInitialize(RO_INIT_MULTITHREADED));
    module = LoadLibraryW(L"windows.security.authentication.onlineid.dll");
    if (!module) { fprintf(stderr, "LoadLibrary error=%lu\n", GetLastError()); return 2; }
    get_factory = (void *)GetProcAddress(module, "DllGetActivationFactory");
    if (!get_factory) return 3;
    CHECK(WindowsCreateString(manager_name, sizeof(manager_name)/sizeof(WCHAR)-1, &name));
    CHECK(get_factory(name, &factory));
    CHECK(IActivationFactory_QueryInterface(factory, &IID_IWebAuthenticationCoreManagerStatics, (void **)&manager));
    CHECK(IWebAuthenticationCoreManagerStatics_QueryInterface(manager, &IID_IWebAuthenticationCoreManagerStatics4, (void **)&manager4));
    CHECK(WindowsCreateString(L"https://login.microsoft.com", 27, &provider_id));
    CHECK(WindowsCreateString(L"common", 6, &authority));
    if (argc == 3 && !token && !record) CHECK(WindowsCreateString(L"invalid", 7, &client_id));
    else CHECK(WindowsCreateString(L"11111111-1111-1111-1111-111111111111", 36, &client_id));
    CHECK(IWebAuthenticationCoreManagerStatics_FindAccountProviderWithAuthorityAsync(manager, provider_id, authority, &provider_operation));
    CHECK(wait_result((IUnknown *)provider_operation));
    CHECK(IAsyncOperation_WebAccountProvider_GetResults(provider_operation, &provider));
    if (token)
    {
        IActivationFactory *request_factory;
        IWebTokenRequestFactory *constructor;
        IWebTokenRequest *request;
        IAsyncOperation_WebTokenRequestResult *token_operation;
        IWebTokenRequestResult *token_result;
        WebTokenRequestStatus token_status;
        HSTRING request_name, scope;
        static const WCHAR request_class[] = L"Windows.Security.Authentication.Web.Core.WebTokenRequest";

        CHECK(WindowsCreateString(request_class, sizeof(request_class)/sizeof(WCHAR)-1, &request_name));
        CHECK(get_factory(request_name, &request_factory));
        CHECK(IActivationFactory_QueryInterface(request_factory, &IID_IWebTokenRequestFactory, (void **)&constructor));
        CHECK(WindowsCreateString(L"openid", 6, &scope));
        CHECK(IWebTokenRequestFactory_Create(constructor, provider, scope, client_id, &request));
        if (interactive) CHECK(IWebAuthenticationCoreManagerStatics_RequestTokenAsync(manager, request, &token_operation));
        else CHECK(IWebAuthenticationCoreManagerStatics_GetTokenSilentlyAsync(manager, request, &token_operation));
        CHECK(wait_result((IUnknown *)token_operation));
        CHECK(IAsyncOperation_WebTokenRequestResult_GetResults(token_operation, &token_result));
        CHECK(IWebTokenRequestResult_get_ResponseStatus(token_result, &token_status));
        if (token_status == WebTokenRequestStatus_Success)
        {
            IVectorView_WebTokenResponse *responses;
            IWebTokenResponse *response;
            HSTRING access;
            CHECK(IWebTokenRequestResult_get_ResponseData(token_result, &responses));
            CHECK(IVectorView_WebTokenResponse_get_Size(responses, &count));
            if (count != 1) return 8;
            CHECK(IVectorView_WebTokenResponse_GetAt(responses, 0, &response));
            CHECK(IWebTokenResponse_get_Token(response, &access));
            if (wcscmp(WindowsGetStringRawBuffer(access, NULL), L"fixture-access-not-a-token")) return 9;
            WindowsDeleteString(access);
            IWebTokenResponse_Release(response);IVectorView_WebTokenResponse_Release(responses);
        }
        else
        {
            CHECK(IWebTokenRequestResult_get_ResponseError(token_result, &error));
            CHECK(IWebProviderError_get_ErrorCode(error, &error_code));
            IWebProviderError_Release(error);
        }
        status = (FindAllWebAccountsStatus)token_status;
        IWebTokenRequestResult_Release(token_result);
        IAsyncOperation_WebTokenRequestResult_Release(token_operation);
        IWebTokenRequest_Release(request);
        IWebTokenRequestFactory_Release(constructor);
        IActivationFactory_Release(request_factory);
        WindowsDeleteString(scope);WindowsDeleteString(request_name);
    }
    else
    {
        CHECK(IWebAuthenticationCoreManagerStatics4_FindAllAccountsWithClientIdAsync(manager4, provider, client_id, &operation));
        CHECK(wait_result((IUnknown *)operation));
        CHECK(IAsyncOperation_FindAllAccountsResult_GetResults(operation, &result));
        CHECK(IFindAllAccountsResult_get_Status(result, &status));
        if (status == FindAllWebAccountsStatus_Success)
        {
            CHECK(IFindAllAccountsResult_get_Accounts(result, &accounts));
            CHECK(IVectorView_WebAccount_get_Size(accounts, &count));
            if (record)
            {
                IWebAccount *account;
                IWebAccount2 *account2;
                HSTRING username, id;
                if (count != 1) return 6;
                CHECK(IVectorView_WebAccount_GetAt(accounts, 0, &account));
                CHECK(IWebAccount_get_UserName(account, &username));
                CHECK(IWebAccount_QueryInterface(account, &IID_IWebAccount2, (void **)&account2));
                CHECK(IWebAccount2_get_Id(account2, &id));
                if (wcscmp(WindowsGetStringRawBuffer(username, NULL), L"fixture-user@example.invalid") ||
                    wcscmp(WindowsGetStringRawBuffer(id, NULL), L"fixture-account-id")) return 7;
                WindowsDeleteString(username);WindowsDeleteString(id);
                IWebAccount2_Release(account2);IWebAccount_Release(account);
            }
            IVectorView_WebAccount_Release(accounts);
        }
        else
        {
            CHECK(IFindAllAccountsResult_get_ProviderError(result, &error));
            CHECK(IWebProviderError_get_ErrorCode(error, &error_code));
            IWebProviderError_Release(error);
        }
        IFindAllAccountsResult_Release(result);
        IAsyncOperation_FindAllAccountsResult_Release(operation);
    }
    if (!(file = fopen(argv[1], "wb"))) return 4;
    fprintf(file, "%lu %u %08x %u\n", GetCurrentProcessId(), status, (unsigned)error_code, (unsigned)count);
    if (fclose(file)) return 5;
    IWebAccountProvider_Release(provider);
    IAsyncOperation_WebAccountProvider_Release(provider_operation);
    IWebAuthenticationCoreManagerStatics4_Release(manager4);
    IWebAuthenticationCoreManagerStatics_Release(manager);
    IActivationFactory_Release(factory);
    WindowsDeleteString(client_id);WindowsDeleteString(authority);WindowsDeleteString(provider_id);WindowsDeleteString(name);
    RoUninitialize();
    return 0;
}
