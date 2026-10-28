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

static BOOL device, async_cancel;
static volatile LONG dialog_seen, action_taken, dialog_closed;
static IAsyncInfo *cancel_info;
static HWND prompt_window;

static BOOL CALLBACK find_prompt(HWND window, LPARAM data)
{
    WCHAR title[128];
    DWORD pid;
    (void)data;
    GetWindowThreadProcessId(window, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(window) &&
        GetWindowTextW(window, title, sizeof(title)/sizeof(WCHAR)) && !wcscmp(title, L"Microsoft 365 sign-in"))
    { prompt_window = window; return FALSE; }
    return TRUE;
}

static BOOL marker_exists(const char *name)
{
    char path[4096];
    DWORD size = GetEnvironmentVariableA(name, path, sizeof(path));
    return size && size < sizeof(path) && GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static DWORD WINAPI watch_prompt(void *context)
{
    char path[4096], action[32] = {0};
    DWORD start = GetTickCount(), size;
    FILE *file;
    (void)context;
    if (FAILED(RoInitialize(RO_INIT_MULTITHREADED))) return 7;
    while (!prompt_window && GetTickCount() - start < 20000)
    { EnumWindows(find_prompt, 0); if (!prompt_window) Sleep(20); }
    if (!prompt_window) return 1;
    InterlockedExchange(&dialog_seen, 1);
    size = GetEnvironmentVariableA("EAGLE_FIXTURE_PROMPT_READY", path, sizeof(path));
    if (!size || size >= sizeof(path) || !(file = fopen(path, "wb"))) return 2;
    fprintf(file, "%lu\n", (unsigned long)(ULONG_PTR)prompt_window);fclose(file);
    start = GetTickCount();
    while (!marker_exists("EAGLE_FIXTURE_PROMPT_CLICK") && GetTickCount() - start < 20000) Sleep(20);
    if (!marker_exists("EAGLE_FIXTURE_PROMPT_CLICK")) return 3;
    GetEnvironmentVariableA("EAGLE_FIXTURE_PROMPT_ACTION", action, sizeof(action));
    if (async_cancel)
    {
        if (FAILED(IAsyncInfo_Cancel(cancel_info))) return 4;
    }
    else
    {
        HWND button = GetDlgItem(prompt_window, !strcmp(action, "cancel") ? IDCANCEL : IDOK);
        if (!button || !IsWindowEnabled(button)) return 5;
        SendMessageW(button, BM_CLICK, 0, 0);
    }
    InterlockedExchange(&action_taken, 1);
    start = GetTickCount();
    while (IsWindow(prompt_window) && GetTickCount() - start < 10000) Sleep(20);
    if (IsWindow(prompt_window)) return 6;
    InterlockedExchange(&dialog_closed, 1);
    RoUninitialize();
    return 0;
}

static BOOL register_fixture_uri(void)
{
    char executable[4096], output[4096], command[8300];
    HKEY key, child;
    LONG result;
    DWORD exe_size = GetEnvironmentVariableA("EAGLE_FIXTURE_URI_EXE", executable, sizeof(executable));
    DWORD out_size = GetEnvironmentVariableA("EAGLE_FIXTURE_URI_LOG", output, sizeof(output));
    if (!exe_size || exe_size >= sizeof(executable) || !out_size || out_size >= sizeof(output)) return FALSE;
    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, "eagle-fixture", 0, NULL, 0, KEY_WRITE, NULL, &key, NULL)) return FALSE;
    result = RegSetValueExA(key, "URL Protocol", 0, REG_SZ, (const BYTE *)"", 1);
    if (!result) result = RegCreateKeyExA(key, "shell\\open\\command", 0, NULL, 0, KEY_WRITE, NULL, &child, NULL);
    if (!result)
    {
        snprintf(command, sizeof(command), "\"%s\" \"%%1\" \"%s\"", executable, output);
        result = RegSetValueExA(child, NULL, 0, REG_SZ, (BYTE *)command, strlen(command)+1);
        RegCloseKey(child);
    }
    RegCloseKey(key);
    return !result;
}

static HRESULT wait_result(IUnknown *value)
{
    IAsyncInfo *info;
    AsyncStatus status = Started;
    unsigned i;
    HRESULT hr = IUnknown_QueryInterface(value, &IID_IAsyncInfo, (void **)&info);
    if (FAILED(hr)) return hr;
    for (i = 0; i < (device ? 3000 : 1000) && status == Started; i++)
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
    BOOL token, interactive, record, force, personal, batch, enumerate;
    const WCHAR *account_authority = L"common";
    char result_path[MAX_PATH];
    FILE *file;
    if (argc != 2 && (argc != 3 || (strcmp(argv[2], "invalid") && strcmp(argv[2], "silent") && strcmp(argv[2], "interactive") && strcmp(argv[2], "record") && strcmp(argv[2], "refresh") && strcmp(argv[2], "refresh-interactive") && strcmp(argv[2], "device") && strcmp(argv[2], "forced") && strcmp(argv[2], "forced-silent") && strcmp(argv[2], "batch") && strcmp(argv[2], "personal") && strcmp(argv[2], "organization") && strncmp(argv[2], "accounts-", 9)))) return 1;
    enumerate = argc == 3 && !strncmp(argv[2], "accounts-", 9);
    if (enumerate)
    {
        account_authority = !strcmp(argv[2], "accounts-common") ? L"common" :
                            !strcmp(argv[2], "accounts-organization") ? L"organizations" :
                            !strcmp(argv[2], "accounts-tenant") ? L"9188040d-6c67-4c5b-b112-36a304b66dad" : L"consumers";
    }
    batch = argc == 3 && !strcmp(argv[2], "batch");
    personal = batch || (argc == 3 && (!strcmp(argv[2], "personal") || !strcmp(argv[2], "organization")));
    device = argc == 3 && !strcmp(argv[2], "device");
    if (device)
    {
        char action[32] = {0};
        GetEnvironmentVariableA("EAGLE_FIXTURE_PROMPT_ACTION", action, sizeof(action));
        async_cancel = !strcmp(action, "async");
        if (!register_fixture_uri()) return 10;
    }
    force = argc == 3 && (!strcmp(argv[2], "forced") || !strcmp(argv[2], "forced-silent"));
    record = argc == 3 && !strcmp(argv[2], "record");
    token = personal || force || device || (argc == 3 && (!strcmp(argv[2], "silent") || !strcmp(argv[2], "interactive") || !strcmp(argv[2], "refresh") || !strcmp(argv[2], "refresh-interactive")));
    interactive = personal || (force && !strcmp(argv[2], "forced")) || device || (token && (!strcmp(argv[2], "interactive") || !strcmp(argv[2], "refresh-interactive")));
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
    CHECK(WindowsCreateString(account_authority, wcslen(account_authority), &authority));
    if (argc == 3 && !token && !record && !enumerate) CHECK(WindowsCreateString(L"invalid", 7, &client_id));
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
        IWebTokenRequestResult *token_result = NULL;
        HANDLE watcher_thread = NULL;
        WebTokenRequestStatus token_status;
        HSTRING request_name, scope;
        static const WCHAR request_class[] = L"Windows.Security.Authentication.Web.Core.WebTokenRequest";

        CHECK(WindowsCreateString(request_class, sizeof(request_class)/sizeof(WCHAR)-1, &request_name));
        CHECK(get_factory(request_name, &request_factory));
        CHECK(IActivationFactory_QueryInterface(request_factory, &IID_IWebTokenRequestFactory, (void **)&constructor));
        CHECK(WindowsCreateString(L"openid", 6, &scope));
        CHECK(IWebTokenRequestFactory_CreateWithPromptType(constructor, provider, scope, client_id,
                force ? WebTokenRequestPromptType_ForceAuthentication : WebTokenRequestPromptType_Default, &request));
        if (batch)
        {
            IMap_HSTRING_HSTRING *properties;
            HSTRING key, value;
            boolean replaced;
            CHECK(IWebTokenRequest_get_Properties(request, &properties));
            CHECK(WindowsCreateString(L"oauth2_batch", 12, &key));
            CHECK(WindowsCreateString(L"1", 1, &value));
            CHECK(IMap_HSTRING_HSTRING_Insert(properties, key, value, &replaced));
            WindowsDeleteString(key);WindowsDeleteString(value);
            IMap_HSTRING_HSTRING_Release(properties);
        }
        if (interactive) CHECK(IWebAuthenticationCoreManagerStatics_RequestTokenAsync(manager, request, &token_operation));
        else CHECK(IWebAuthenticationCoreManagerStatics_GetTokenSilentlyAsync(manager, request, &token_operation));
        if (device)
        {
            CHECK(IAsyncOperation_WebTokenRequestResult_QueryInterface(token_operation, &IID_IAsyncInfo, (void **)&cancel_info));
            watcher_thread = CreateThread(NULL, 0, watch_prompt, NULL, 0, NULL);
            if (!watcher_thread) return 11;
        }
        if (async_cancel)
        {
            AsyncStatus state = Started;
            HRESULT cancellation;
            unsigned i;
            for (i = 0; i < 3000 && state == Started; i++)
            { CHECK(IAsyncInfo_get_Status(cancel_info, &state)); if (state == Started) Sleep(10); }
            CHECK(IAsyncInfo_get_ErrorCode(cancel_info, &cancellation));
            if (state != Canceled || cancellation != E_ABORT ||
                IAsyncOperation_WebTokenRequestResult_GetResults(token_operation, &token_result) != E_ILLEGAL_METHOD_CALL || token_result) return 12;
            token_status = (WebTokenRequestStatus)Canceled;
            error_code = (UINT32)cancellation;
        }
        else
        {
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
                if (batch)
                {
                    const WCHAR *text = WindowsGetStringRawBuffer(access, NULL);
                    if (!wcsstr(text, L"access_token=fixture-access-not-a-token&") ||
                        !wcsstr(text, L"&id_token=fixture-id-not-a-token&") ||
                        !wcsstr(text, L"&client_info=fixture-client-info&") ||
                        !wcsstr(text, L"&scope=openid%20profile&token_type=Bearer&expires_in=")) return 9;
                }
                else if (wcscmp(WindowsGetStringRawBuffer(access, NULL), L"fixture-access-not-a-token")) return 9;
                if (personal)
                {
                    IWebAccount *account;
                    IWebAccount2 *account2;
                    IMapView_HSTRING_HSTRING *properties;
                    HSTRING key, value = NULL;
                    HRESULT hr;
                    CHECK(IWebTokenResponse_get_WebAccount(response, &account));
                    CHECK(IWebAccount_QueryInterface(account, &IID_IWebAccount2, (void **)&account2));
                    CHECK(IWebAccount2_get_Properties(account2, &properties));
                    CHECK(WindowsCreateString(L"SafeCustomerId", 14, &key));
                    hr = IMapView_HSTRING_HSTRING_Lookup(properties, key, &value);
                    if (!strcmp(argv[2], "organization"))
                    {
                        if (hr != E_BOUNDS || value) return 15;
                    }
                    else if (FAILED(hr) || wcscmp(WindowsGetStringRawBuffer(value, NULL), L"123456789abcdef0")) return 15;
                    WindowsDeleteString(key);WindowsDeleteString(value);
                    IMapView_HSTRING_HSTRING_Release(properties);IWebAccount2_Release(account2);IWebAccount_Release(account);
                }
                WindowsDeleteString(access);
                IWebTokenResponse_Release(response);IVectorView_WebTokenResponse_Release(responses);
            }
            else
            {
                CHECK(IWebTokenRequestResult_get_ResponseError(token_result, &error));
                CHECK(IWebProviderError_get_ErrorCode(error, &error_code));
                IWebProviderError_Release(error);
            }
        }
        if (device)
        {
            DWORD result;
            if (WaitForSingleObject(watcher_thread, 20000) != WAIT_OBJECT_0 ||
                !GetExitCodeThread(watcher_thread, &result) || result || !dialog_seen || !action_taken || !dialog_closed) return 13;
            CloseHandle(watcher_thread);IAsyncInfo_Release(cancel_info);
        }
        status = (FindAllWebAccountsStatus)token_status;
        if (token_result) IWebTokenRequestResult_Release(token_result);
        IAsyncOperation_WebTokenRequestResult_Release(token_operation);
        IWebTokenRequest_Release(request);
        IWebTokenRequestFactory_Release(constructor);
        IActivationFactory_Release(request_factory);
        WindowsDeleteString(scope);WindowsDeleteString(request_name);
    }
    else
    {
        if (enumerate && !strcmp(argv[2], "accounts-all"))
            CHECK(IWebAuthenticationCoreManagerStatics4_FindAllAccountsAsync(manager4, provider, &operation));
        else
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
            if (enumerate)
            {
                IWebAccount *account;
                IWebAccount2 *account2;
                IMapView_HSTRING_HSTRING *properties;
                HSTRING key, value = NULL;
                HRESULT hr;
                if (count != 1) return 16;
                CHECK(IVectorView_WebAccount_GetAt(accounts, 0, &account));
                CHECK(IWebAccount_QueryInterface(account, &IID_IWebAccount2, (void **)&account2));
                CHECK(IWebAccount2_get_Properties(account2, &properties));
                CHECK(WindowsCreateString(L"SafeCustomerId", 14, &key));
                hr = IMapView_HSTRING_HSTRING_Lookup(properties, key, &value);
                if (!strcmp(argv[2], "accounts-common") || !strcmp(argv[2], "accounts-organization") ||
                    !strcmp(argv[2], "accounts-malformed"))
                {
                    if (hr != E_BOUNDS || value) return 17;
                }
                else if (FAILED(hr) || wcscmp(WindowsGetStringRawBuffer(value, NULL),
                         !strcmp(argv[2], "accounts-uppercase") ? L"abcdef0123456789" : L"123456789abcdef0")) return 17;
                WindowsDeleteString(key);WindowsDeleteString(value);
                IMapView_HSTRING_HSTRING_Release(properties);IWebAccount2_Release(account2);IWebAccount_Release(account);
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
    if (snprintf(result_path, sizeof(result_path), "%s.tmp", argv[1]) >= (int)sizeof(result_path)) return 4;
    if (!(file = fopen(result_path, "wb"))) return 4;
    fprintf(file, "%lu %u %08x %u\n", GetCurrentProcessId(), status, (unsigned)error_code, (unsigned)count);
    if (device) fprintf(file, "%ld %ld %ld\n", dialog_seen, action_taken, dialog_closed);
    if (fclose(file)) return 5;
    if (!MoveFileExA(result_path, argv[1], MOVEFILE_REPLACE_EXISTING)) return 5;
    IWebAccountProvider_Release(provider);
    IAsyncOperation_WebAccountProvider_Release(provider_operation);
    IWebAuthenticationCoreManagerStatics4_Release(manager4);
    IWebAuthenticationCoreManagerStatics_Release(manager);
    IActivationFactory_Release(factory);
    WindowsDeleteString(client_id);WindowsDeleteString(authority);WindowsDeleteString(provider_id);WindowsDeleteString(name);
    RoUninitialize();
    if (device)
    {
        DWORD start = GetTickCount();
        while (!marker_exists("EAGLE_FIXTURE_PROMPT_FINISH") && GetTickCount() - start < 20000) Sleep(20);
        if (!marker_exists("EAGLE_FIXTURE_PROMPT_FINISH")) return 14;
    }
    return 0;
}
