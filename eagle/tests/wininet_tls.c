#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE start;
static INTERNET_PORT port;
static LONG completed;

static BOOL request(void)
{
    HINTERNET session = NULL, connection = NULL, request = NULL;
    DWORD timeout = 5000, status, size, count, total = 0;
    char body[64];
    const char expected[] = "Eagle loopback TLS\n";
    BOOL result = FALSE;

    session = InternetOpenW(L"Eagle owned TLS fixture", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!session) goto done;
    if (!InternetSetOptionW(session, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout)) ||
        !InternetSetOptionW(session, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout)) ||
        !InternetSetOptionW(session, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout))) goto done;
    connection = InternetConnectW(session, L"localhost", port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!connection) goto done;
    request = HttpOpenRequestW(connection, L"GET", L"/owned-fixture", NULL, NULL, NULL,
                              INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT, 0);
    if (!request || !HttpSendRequestW(request, NULL, 0, NULL, 0)) goto done;
    size = sizeof(status);
    if (!HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status, &size, NULL) || status != 200) goto done;
    do
    {
        count = 0;
        if (total == sizeof(body) || !InternetReadFile(request, body + total, sizeof(body) - total, &count)) goto done;
        total += count;
    } while (count);
    result = total == sizeof(expected) - 1 && !memcmp(body, expected, total);
done:
    if (!result) fprintf(stderr, "WinINet fixture request error=%lu\n", GetLastError());
    if (request) InternetCloseHandle(request);
    if (connection) InternetCloseHandle(connection);
    if (session) InternetCloseHandle(session);
    return result;
}

static DWORD WINAPI worker(void *argument)
{
    unsigned i;
    (void)argument;
    if (WaitForSingleObject(start, 10000) != WAIT_OBJECT_0) return 1;
    for (i = 0; i < 4; i++)
    {
        if (!request()) return 2;
        InterlockedIncrement(&completed);
    }
    return 0;
}

int main(int argc, char **argv)
{
    BYTE encoded[16384];
    FILE *file;
    HCERTSTORE store;
    PCCERT_CONTEXT certificate = NULL;
    HANDLE threads[4];
    DWORD code;
    unsigned i, count = 0;
    size_t size;
    char *end;
    unsigned long parsed;
    BOOL ok = TRUE;

    if (argc != 3 || !(parsed = strtoul(argv[1], &end, 10)) || *end || parsed > 65535) return 2;
    port = parsed;
    if (!(file = fopen(argv[2], "rb"))) return 3;
    size = fread(encoded, 1, sizeof(encoded), file);
    ok = size && feof(file) && !ferror(file);
    fclose(file);
    if (!ok) return 4;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store) return 5;
    if (!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, encoded, size,
                                         CERT_STORE_ADD_REPLACE_EXISTING, &certificate))
    {
        CertCloseStore(store, 0);
        return 6;
    }
    if (!CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL))
    {
        CertDeleteCertificateFromStore(certificate);
        CertCloseStore(store, 0);
        return 8;
    }
    start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start) ok = FALSE;
    else
    {
        for (i = 0; i < ARRAYSIZE(threads); i++)
        {
            if (!(threads[count] = CreateThread(NULL, 0, worker, NULL, 0, NULL))) break;
            count++;
        }
        if (!SetEvent(start) || !count || WaitForMultipleObjects(count, threads, TRUE, 45000) != WAIT_OBJECT_0)
            ExitProcess(7);
        for (i = 0; i < count; i++)
        {
            if (!GetExitCodeThread(threads[i], &code) || code) ok = FALSE;
            CloseHandle(threads[i]);
        }
        CloseHandle(start);
    }
    if (!CertDeleteCertificateFromStore(certificate)) ok = FALSE;
    if (!CertCloseStore(store, 0)) ok = FALSE;
    return !ok || count != ARRAYSIZE(threads) || completed != 16;
}
