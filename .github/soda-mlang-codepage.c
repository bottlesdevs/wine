#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <mlang.h>
#include <stdio.h>
#include <string.h>

static void detect(IMultiLanguage2 *language, const char *name, const char *text)
{
    DetectEncodingInfo scores[8];
    INT size = (INT)strlen(text), count = 8, i;
    HRESULT hr;
    IStream *stream;
    ULONG written;
    LARGE_INTEGER start;

    memset(scores, 0, sizeof(scores));
    hr = IMultiLanguage2_DetectInputCodepage(language, 0, 1252, (CHAR *)text, &size, scores, &count);
    printf("case=%s api=DetectInputCodepage hr=%#lx consumed=%d count=%d", name, hr, size, count);
    if (SUCCEEDED(hr) && count >= 0 && count <= 8)
        for (i = 0; i < count; ++i)
            printf(" cp=%u confidence=%d document=%d", scores[i].nCodePage,
                    scores[i].nConfidence, scores[i].nDocPercent);
    putchar('\n');

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr))
    {
        printf("case=%s api=CreateStreamOnHGlobal hr=%#lx\n", name, hr);
        return;
    }
    hr = IStream_Write(stream, text, (ULONG)strlen(text), &written);
    start.QuadPart = 0;
    if (SUCCEEDED(hr) && written == strlen(text)) hr = IStream_Seek(stream, start, STREAM_SEEK_SET, NULL);
    if (SUCCEEDED(hr))
    {
        memset(scores, 0, sizeof(scores));
        count = 8;
        hr = IMultiLanguage2_DetectCodepageInIStream(language, 0, 1252, stream, scores, &count);
        printf("case=%s api=DetectCodepageInIStream hr=%#lx count=%d", name, hr, count);
        if (SUCCEEDED(hr) && count >= 0 && count <= 8)
            for (i = 0; i < count; ++i)
                printf(" cp=%u confidence=%d document=%d", scores[i].nCodePage,
                        scores[i].nConfidence, scores[i].nDocPercent);
        putchar('\n');
    }
    else printf("case=%s api=PrepareStream hr=%#lx\n", name, hr);
    IStream_Release(stream);
}

int main(void)
{
    static const struct
    {
        const char *name, *text;
    } tests[] =
    {
        {"ascii", "Subject: Local mail fixture\r\nA short message for the codepage control.\r\n"},
        {"utf8", "A message with Italian text: caff\xc3\xa8, citt\xc3\xa0, perch\xc3\xa9.\r\n"},
        {"windows1252", "A message with Italian text: caff\xe8, citt\xe0, perch\xe9.\r\n"},
        {"html", "<html><head><meta charset=\"utf-8\"></head><body>caff\xc3\xa8</body></html>"}
    };
    IMultiLanguage2 *language;
    HRESULT hr;
    unsigned int i;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 1;
    hr = CoCreateInstance(&CLSID_CMultiLanguage, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMultiLanguage2, (void **)&language);
    printf("api=CoCreateInstance hr=%#lx bits=%u\n", hr, (unsigned int)(sizeof(void *) * 8));
    if (FAILED(hr))
    {
        CoUninitialize();
        return 1;
    }
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        detect(language, tests[i].name, tests[i].text);
    IMultiLanguage2_Release(language);
    CoUninitialize();
    return 0;
}
