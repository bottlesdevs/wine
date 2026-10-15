#define _WINHTTP_INTERNAL_
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
struct fixture_handle { unsigned kind; DWORD offset; };
static const char response[] = "{\"expires_in\":3600,\"access_token\":\"fixture-access-not-a-token\",\"refresh_token\":\"fixture-next-refresh-not-a-token\",\"scope\":\"openid\"}";
static const char invalid_response[] = "{\"expires_in\":0}";

static BOOL mode(const char *value)
{
    char buffer[64] = {0};
    DWORD size = GetEnvironmentVariableA("EAGLE_FIXTURE_HTTP_MODE", buffer, sizeof(buffer));
    return size && size < sizeof(buffer) && !strcmp(buffer, value);
}

static void note(const char *method)
{
    char path[4096];
    DWORD size = GetEnvironmentVariableA("EAGLE_FIXTURE_HTTP_LOG", path, sizeof(path));
    FILE *file;
    if (size && size < sizeof(path) && (file = fopen(path, "ab")))
    {
        fprintf(file, "%s\n", method);
        fclose(file);
    }
}

static struct fixture_handle *handle(HINTERNET value, unsigned kind)
{
    struct fixture_handle *result = value;
    if (!result || result->kind != kind) { SetLastError(ERROR_INVALID_HANDLE); return NULL; }
    return result;
}

static HINTERNET create(unsigned kind)
{
    struct fixture_handle *result = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*result));
    if (result) result->kind = kind;
    return result;
}

EXPORT HINTERNET WINAPI WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
{
    if (!mode("success") && !mode("timeout") && !mode("http-error") && !mode("bad-response") && !mode("oversized"))
    { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    note("Open");
    return create(1);
}

EXPORT HINTERNET WINAPI WinHttpConnect(HINTERNET session, LPCWSTR server, INTERNET_PORT port, DWORD reserved)
{
    if (!handle(session, 1) || wcscmp(server, L"login.microsoftonline.com") || port != 443)
    { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    note("Connect");
    return create(2);
}

EXPORT HINTERNET WINAPI WinHttpOpenRequest(HINTERNET connection, LPCWSTR verb, LPCWSTR path, LPCWSTR version,
                                          LPCWSTR referer, LPCWSTR *accept, DWORD flags)
{
    if (!handle(connection, 2) || wcscmp(verb, L"POST") || wcscmp(path, L"/common/oauth2/v2.0/token"))
    { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    note("OpenRequest");
    return create(3);
}

EXPORT BOOL WINAPI WinHttpSetTimeouts(HINTERNET request, int resolve, int connect, int send, int receive)
{
    return handle(request, 3) != NULL;
}

EXPORT BOOL WINAPI WinHttpSendRequest(HINTERNET request, LPCWSTR headers, DWORD header_size, LPVOID optional,
                                      DWORD optional_size, DWORD total, DWORD_PTR context)
{
    char body[2048] = {0};
    if (!handle(request, 3) || !optional || optional_size >= sizeof(body))
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(body, optional, optional_size);
    if (!strstr(body, "grant_type=refresh_token") || !strstr(body, "refresh_token=fixture-refresh-not-a-token") ||
        !strstr(body, "client_id=11111111-1111-1111-1111-111111111111"))
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    note("SendRequest");
    if (mode("timeout")) { SetLastError(ERROR_WINHTTP_TIMEOUT); return FALSE; }
    return TRUE;
}

EXPORT BOOL WINAPI WinHttpReceiveResponse(HINTERNET request, LPVOID reserved)
{
    note("ReceiveResponse");
    return handle(request, 3) != NULL;
}

EXPORT BOOL WINAPI WinHttpQueryHeaders(HINTERNET request, DWORD flags, LPCWSTR name, LPVOID buffer, LPDWORD size, LPDWORD index)
{
    if (!handle(request, 3) || !buffer || !size || *size < sizeof(DWORD)) return FALSE;
    *(DWORD *)buffer = mode("http-error") ? 400 : 200;
    *size = sizeof(DWORD);
    note("QueryHeaders");
    return TRUE;
}

EXPORT BOOL WINAPI WinHttpQueryDataAvailable(HINTERNET request, LPDWORD available)
{
    struct fixture_handle *value = handle(request, 3);
    if (!value || !available) return FALSE;
    *available = mode("oversized") ? 4 * 1024 * 1024 + 1 : strlen(mode("bad-response") ? invalid_response : response) - value->offset;
    return TRUE;
}

EXPORT BOOL WINAPI WinHttpReadData(HINTERNET request, LPVOID buffer, DWORD count, LPDWORD read)
{
    struct fixture_handle *value = handle(request, 3);
    const char *body = mode("bad-response") ? invalid_response : response;
    DWORD remaining;
    if (!value || !buffer || !read) return FALSE;
    remaining = strlen(body) - value->offset;
    *read = count < remaining ? count : remaining;
    memcpy(buffer, body + value->offset, *read);
    value->offset += *read;
    note("ReadData");
    return TRUE;
}

EXPORT BOOL WINAPI WinHttpCloseHandle(HINTERNET value)
{
    struct fixture_handle *entry = value;
    if (!entry || entry->kind < 1 || entry->kind > 3) return FALSE;
    note("Close");
    return HeapFree(GetProcessHeap(), 0, entry);
}
