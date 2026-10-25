#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <stdio.h>
#include <stddef.h>
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Storage_Streams
#include "windows.storage.streams.h"
#define WIDL_using_Windows_Web_Http
#define WIDL_using_Windows_Web_Http_Headers
#include "windows.web.http.h"

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

static HRESULT activate(const WCHAR *name, REFIID iid, void **out)
{
    IInspectable *object = NULL;
    HSTRING value;
    HRESULT hr;

    *out = NULL;
    hr = WindowsCreateString(name, lstrlenW(name), &value);
    if (FAILED(hr)) return hr;
    hr = RoActivateInstance(value, &object);
    WindowsDeleteString(value);
    if (SUCCEEDED(hr))
    {
        hr = IInspectable_QueryInterface(object, iid, out);
        IInspectable_Release(object);
    }
    return hr;
}

static void test_headers(IInspectable *headers, const char *name, const unsigned int *getters,
        unsigned int count, unsigned int append_slot, unsigned int from_slot)
{
    typedef HRESULT (WINAPI *getter)(IInspectable *, IInspectable **);
    typedef HRESULT (WINAPI *append)(IInspectable *, HSTRING, HSTRING);
    typedef HRESULT (WINAPI *try_append)(IInspectable *, HSTRING, HSTRING, boolean *);
    void **table = *(void ***)headers;
    IMap_HSTRING_HSTRING *map = NULL;
    IInspectable *value;
    HSTRING key = NULL, input = NULL, returned = NULL;
    unsigned int i;
    boolean result = FALSE;
    HRESULT hr;

    for (i = 0; i < count; ++i)
    {
        unsigned int slot = getters[i];
        value = (void *)0xdeadbeef;
        hr = ((getter)table[slot])(headers, &value);
        check(hr == (slot == from_slot ? S_OK : E_NOTIMPL) && !value, "property result");
        hr = ((getter)table[slot])(headers, NULL);
        check(hr == E_POINTER, "property null output");
    }
    WindowsCreateString(L"X-Soda-Header", 13, &key);
    WindowsCreateString(L"visible", 7, &input);
    hr = ((append)table[append_slot])(headers, key, input);
    check(hr == S_OK, "SDK Append slot");
    hr = IInspectable_QueryInterface(headers, &IID_IMap_HSTRING_HSTRING, (void **)&map);
    check(hr == S_OK && map, "header map");
    if (map)
    {
        hr = IMap_HSTRING_HSTRING_Lookup(map, key, &returned);
        check(hr == S_OK && !lstrcmpW(WindowsGetStringRawBuffer(returned, NULL), L"visible"), "map sees Append");
        WindowsDeleteString(returned);
        hr = ((try_append)table[append_slot + 1])(headers, key, input, &result);
        check(hr == S_OK && result, "SDK TryAppend slot");
        hr = ((try_append)table[append_slot + 1])(headers, key, input, NULL);
        check(hr == E_POINTER, "TryAppend null output");
        IMap_HSTRING_HSTRING_Release(map);
    }
    WindowsDeleteString(key);
    WindowsDeleteString(input);
    printf("HEADERS %s checked\n", name);
}

static void test_content(const WCHAR *address)
{
    static const unsigned int getters[] = {6, 8, 9, 10, 12, 14, 16, 18, 20, 22};
    IUriRuntimeClassFactory *factory = NULL;
    IUriRuntimeClass *uri = NULL;
    IHttpClient *client = NULL;
    IHttpResponseMessage *response = NULL;
    IHttpRequestMessage *request = NULL;
    IHttpContent *content = NULL;
    IHttpContentHeaderCollection *headers = NULL;
    IAsyncOperationWithProgress_HttpResponseMessage_HttpProgress *operation = NULL;
    IAsyncInfo *info = NULL;
    HSTRING name = NULL, url = NULL;
    AsyncStatus status = Started;
    DWORD started;
    HRESULT hr;

    WindowsCreateString(L"Windows.Foundation.Uri", 22, &name);
    hr = RoGetActivationFactory(name, &IID_IUriRuntimeClassFactory, (void **)&factory);
    check(hr == S_OK && factory, "URI factory");
    WindowsDeleteString(name);
    if (!factory) goto done;
    WindowsCreateString(address, lstrlenW(address), &url);
    hr = IUriRuntimeClassFactory_CreateUri(factory, url, &uri);
    check(hr == S_OK && uri, "loopback URI");
    if (!uri) goto done;
    hr = activate(L"Windows.Web.Http.HttpRequestMessage", &IID_IHttpRequestMessage, (void **)&request);
    check(hr == S_OK && request, "HTTP request");
    if (!request) goto done;
    hr = IHttpRequestMessage_put_RequestUri(request, uri);
    check(hr == S_OK, "request URI");
    hr = activate(L"Windows.Web.Http.HttpClient", &IID_IHttpClient, (void **)&client);
    check(hr == S_OK && client, "HTTP client");
    if (!client) goto done;
    hr = IHttpClient_SendRequestAsync(client, request, &operation);
    check(hr == S_OK && operation, "loopback request");
    if (!operation) goto done;
    hr = IAsyncOperationWithProgress_HttpResponseMessage_HttpProgress_QueryInterface(operation, &IID_IAsyncInfo, (void **)&info);
    check(hr == S_OK && info, "async info");
    if (!info) goto done;
    started = GetTickCount();
    while (status == Started && GetTickCount() - started < 15000)
    {
        hr = IAsyncInfo_get_Status(info, &status);
        if (FAILED(hr)) break;
        Sleep(10);
    }
    check(hr == S_OK && status == Completed, "loopback completion");
    if (status != Completed) goto done;
    hr = IAsyncOperationWithProgress_HttpResponseMessage_HttpProgress_GetResults(operation, &response);
    check(hr == S_OK && response, "HTTP response");
    if (!response) goto done;
    hr = IHttpResponseMessage_get_Content(response, &content);
    check(hr == S_OK && content, "HTTP content");
    if (!content) goto done;
    hr = IHttpContent_get_Headers(content, &headers);
    check(hr == S_OK && headers, "content headers");
    if (headers) test_headers((IInspectable *)headers, "content", getters, ARRAYSIZE(getters), 24, ~0u);
done:
    if (headers) IHttpContentHeaderCollection_Release(headers);
    if (content) IHttpContent_Release(content);
    if (response) IHttpResponseMessage_Release(response);
    if (info) IAsyncInfo_Release(info);
    if (operation) IAsyncOperationWithProgress_HttpResponseMessage_HttpProgress_Release(operation);
    if (client) IHttpClient_Release(client);
    if (request) IHttpRequestMessage_Release(request);
    if (uri) IUriRuntimeClass_Release(uri);
    if (factory) IUriRuntimeClassFactory_Release(factory);
    WindowsDeleteString(url);
}

int wmain(int argc, WCHAR **argv)
{
    static const unsigned int request_getters[] = {6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 27, 29, 31, 32};
    static const unsigned int response_getters[] = {6, 8, 9, 10, 11, 13, 15, 16, 18, 19};
    IHttpRequestMessage *request = NULL;
    IHttpResponseMessage *response = NULL;
    IHttpRequestHeaderCollection *request_headers = NULL;
    IHttpResponseHeaderCollection *response_headers = NULL;
    HRESULT hr;

    check(offsetof(IHttpRequestHeaderCollectionVtbl, Append) == 33 * sizeof(void *), "request SDK layout");
    check(offsetof(IHttpResponseHeaderCollectionVtbl, Append) == 20 * sizeof(void *), "response SDK layout");
    check(offsetof(IHttpContentHeaderCollectionVtbl, Append) == 24 * sizeof(void *), "content SDK layout");
    if (failures) goto done;
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    check(hr == S_OK || hr == S_FALSE, "WinRT initialization");
    if (FAILED(hr)) goto done;
    hr = activate(L"Windows.Web.Http.HttpRequestMessage", &IID_IHttpRequestMessage, (void **)&request);
    check(hr == S_OK && request, "request activation");
    if (request)
    {
        hr = IHttpRequestMessage_get_Headers(request, &request_headers);
        check(hr == S_OK && request_headers, "request headers");
        if (request_headers) test_headers((IInspectable *)request_headers, "request", request_getters,
                ARRAYSIZE(request_getters), 33, 17);
    }
    hr = activate(L"Windows.Web.Http.HttpResponseMessage", &IID_IHttpResponseMessage, (void **)&response);
    check(hr == S_OK && response, "response activation");
    if (response)
    {
        hr = IHttpResponseMessage_get_Headers(response, &response_headers);
        check(hr == S_OK && response_headers, "response headers");
        if (response_headers) test_headers((IInspectable *)response_headers, "response", response_getters,
                ARRAYSIZE(response_getters), 20, ~0u);
    }
    check(argc == 2, "loopback URL argument");
    if (argc == 2) test_content(argv[1]);
    if (request_headers) IHttpRequestHeaderCollection_Release(request_headers);
    if (response_headers) IHttpResponseHeaderCollection_Release(response_headers);
    if (request) IHttpRequestMessage_Release(request);
    if (response) IHttpResponseMessage_Release(response);
    RoUninitialize();
done:
    printf("HTTP_HEADER_ABI_RESULT checks=%u failures=%u\n", checks, failures);
    return !!failures;
}
