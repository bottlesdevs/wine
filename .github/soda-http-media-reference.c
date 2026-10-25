#define COBJMACROS
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <stdio.h>
#include <string.h>

static const GUID media_factory_iid = {0xbed747a8,0xcd17,0x42dd,{0x93,0x67,0xab,0x9c,0x5b,0x56,0xdd,0x7d}};
static const GUID media_statics_iid = {0xe04d83df,0x1d41,0x4d8c,{0xa2,0xde,0x6f,0xd2,0xed,0x87,0x39,0x9b}};
static const GUID name_factory_iid = {0x770e2267,0xcbf8,0x4736,{0xa9,0x25,0x93,0xfb,0xe1,0x0c,0x7c,0xa8}};
static const GUID name_statics_iid = {0xffd4030f,0x1130,0x4152,{0x86,0x59,0x25,0x69,0x09,0xa9,0xd1,0x15}};
static const GUID stringable_iid = {0x96369f54,0x8eb6,0x48f0,{0xab,0xce,0xc1,0xb2,0x11,0xe6,0x27,0xc3}};

typedef HRESULT (WINAPI *get_string)(IInspectable *, HSTRING *);
typedef HRESULT (WINAPI *set_string)(IInspectable *, HSTRING);
typedef HRESULT (WINAPI *get_object)(IInspectable *, IInspectable **);
typedef HRESULT (WINAPI *parse)(IInspectable *, HSTRING, IInspectable **);
typedef HRESULT (WINAPI *try_parse)(IInspectable *, HSTRING, IInspectable **, boolean *);
typedef HRESULT (WINAPI *create_pair)(IInspectable *, HSTRING, HSTRING, IInspectable **);
typedef HRESULT (WINAPI *vector_size)(IInspectable *, UINT32 *);
typedef HRESULT (WINAPI *vector_get)(IInspectable *, UINT32, IInspectable **);
typedef HRESULT (WINAPI *vector_append)(IInspectable *, IInspectable *);

static void **table(IInspectable *object)
{
    return *(void ***)object;
}

static HSTRING string(const WCHAR *value)
{
    HSTRING result = NULL;
    if (value && FAILED(WindowsCreateString(value, (UINT32)lstrlenW(value), &result))) ExitProcess(2);
    return result;
}

static void print_string(HSTRING value)
{
    const WCHAR *data;
    UINT32 length, i;
    data = WindowsGetStringRawBuffer(value, &length);
    putchar('"');
    for (i = 0; i < length; ++i)
    {
        WCHAR ch = data[i];
        if (ch == '"' || ch == '\\') printf("\\%c", (char)ch);
        else if (ch >= 32 && ch < 127) putchar((char)ch);
        else printf("\\u%04x", (unsigned int)ch);
    }
    putchar('"');
}

static void print_property(IInspectable *object, UINT32 slot, const char *name)
{
    HSTRING value = NULL;
    HRESULT hr = ((get_string)table(object)[slot])(object, &value);
    printf(",\"%s_hr\":\"%08lx\",\"%s\":", name, (unsigned long)hr, name);
    print_string(value);
    WindowsDeleteString(value);
}

static void print_value(IInspectable *object, BOOL media)
{
    IInspectable *stringable = NULL, *parameters = NULL, *parameter = NULL;
    HSTRING text = NULL;
    UINT32 size = 0, i;
    HRESULT hr;

    print_property(object, media ? 8 : 6, media ? "media" : "name");
    print_property(object, media ? 6 : 7, media ? "charset" : "value");
    hr = IInspectable_QueryInterface(object, &stringable_iid, (void **)&stringable);
    printf(",\"stringable_hr\":\"%08lx\"", (unsigned long)hr);
    if (stringable)
    {
        hr = ((get_string)table(stringable)[6])(stringable, &text);
        printf(",\"text_hr\":\"%08lx\",\"text\":", (unsigned long)hr);
        print_string(text);
        WindowsDeleteString(text);
        IInspectable_Release(stringable);
    }
    if (!media) return;
    hr = ((get_object)table(object)[10])(object, &parameters);
    printf(",\"parameters_hr\":\"%08lx\"", (unsigned long)hr);
    if (!parameters) return;
    hr = ((vector_size)table(parameters)[7])(parameters, &size);
    printf(",\"size_hr\":\"%08lx\",\"parameters\":[", (unsigned long)hr);
    if (size > 32) ExitProcess(3);
    for (i = 0; i < size; ++i)
    {
        hr = ((vector_get)table(parameters)[6])(parameters, i, &parameter);
        if (i) putchar(',');
        printf("{\"index\":%u,\"hr\":\"%08lx\"", (unsigned int)i, (unsigned long)hr);
        if (parameter)
        {
            print_property(parameter, 6, "name");
            print_property(parameter, 7, "value");
            IInspectable_Release(parameter);
            parameter = NULL;
        }
        putchar('}');
    }
    putchar(']');
    IInspectable_Release(parameters);
}

static void test_parse(IInspectable *factory, UINT32 slot, BOOL use_try, BOOL media,
        const WCHAR *input, const char *operation)
{
    IInspectable *object = NULL;
    HSTRING value = string(input);
    boolean parsed = 0;
    HRESULT hr;

    if (use_try) hr = ((try_parse)table(factory)[slot])(factory, value, &object, &parsed);
    else hr = ((parse)table(factory)[slot])(factory, value, &object);
    printf("{\"operation\":\"%s\",\"input\":", operation);
    if (input) print_string(value); else printf("null");
    printf(",\"hr\":\"%08lx\",\"parsed\":%u,\"object\":%s", (unsigned long)hr,
            (unsigned int)parsed, object ? "true" : "false");
    if (object)
    {
        print_value(object, media);
        IInspectable_Release(object);
    }
    printf("}\n");
    WindowsDeleteString(value);
}

static void test_pair_values(IInspectable *factory)
{
    static const WCHAR *names[] = {L"x", L"name", L"filename", L"charset"};
    static const WCHAR *values[] = {NULL, L"", L"value", L"a b", L"\"utf-8\"", L"a\r\nb", L"a\\b", L"a\"b", L"\x00e9"};
    IInspectable *object;
    HSTRING name, value;
    unsigned int i, j;
    HRESULT hr;

    for (i = 0; i < ARRAYSIZE(names); ++i)
        for (j = 0; j < ARRAYSIZE(values); ++j)
        {
            name = string(names[i]);
            value = string(values[j]);
            object = NULL;
            hr = ((create_pair)table(factory)[7])(factory, name, value, &object);
            printf("{\"operation\":\"pair_create\",\"name_index\":%u,\"value_index\":%u,\"hr\":\"%08lx\"", i, j, (unsigned long)hr);
            if (object)
            {
                print_value(object, FALSE);
                IInspectable_Release(object);
            }
            printf("}\n");
            WindowsDeleteString(name);
            WindowsDeleteString(value);
        }
}

static void test_mutations(IInspectable *factory, IInspectable *name_factory)
{
    static const WCHAR *charsets[] = {L"utf-8", L"\"utf-8\"", L"UTF-16", L"bad value", L"", NULL};
    static const WCHAR *medias[] = {L"application/json", L"text/html; q=1", L" TEXT/HTML ", L"", NULL};
    IInspectable *object = NULL, *parameters = NULL, *parameter = NULL;
    HSTRING initial = string(L"text/plain"), value, name;
    HRESULT hr;
    unsigned int i;

    hr = ((parse)table(factory)[6])(factory, initial, &object);
    WindowsDeleteString(initial);
    if (FAILED(hr) || !object) ExitProcess(4);
    for (i = 0; i < ARRAYSIZE(charsets); ++i)
    {
        value = string(charsets[i]);
        hr = ((set_string)table(object)[7])(object, value);
        printf("{\"operation\":\"set_charset\",\"index\":%u,\"hr\":\"%08lx\"", i, (unsigned long)hr);
        print_value(object, TRUE);
        printf("}\n");
        WindowsDeleteString(value);
    }
    for (i = 0; i < ARRAYSIZE(medias); ++i)
    {
        value = string(medias[i]);
        hr = ((set_string)table(object)[9])(object, value);
        printf("{\"operation\":\"set_media\",\"index\":%u,\"hr\":\"%08lx\"", i, (unsigned long)hr);
        print_value(object, TRUE);
        printf("}\n");
        WindowsDeleteString(value);
    }
    hr = ((get_object)table(object)[10])(object, &parameters);
    if (FAILED(hr) || !parameters) ExitProcess(5);
    name = string(L"charset");
    value = string(L"iso-8859-1");
    hr = ((create_pair)table(name_factory)[7])(name_factory, name, value, &parameter);
    WindowsDeleteString(name);
    WindowsDeleteString(value);
    if (FAILED(hr) || !parameter) ExitProcess(6);
    hr = ((vector_append)table(parameters)[13])(parameters, parameter);
    printf("{\"operation\":\"append_charset\",\"hr\":\"%08lx\"", (unsigned long)hr);
    print_value(object, TRUE);
    printf("}\n");
    value = string(L"utf-16");
    hr = ((set_string)table(parameter)[8])(parameter, value);
    WindowsDeleteString(value);
    printf("{\"operation\":\"mutate_parameter\",\"hr\":\"%08lx\"", (unsigned long)hr);
    print_value(object, TRUE);
    printf("}\n");
    IInspectable_Release(parameter);
    IInspectable_Release(parameters);
    IInspectable_Release(object);
}

int main(void)
{
    static const WCHAR *media_inputs[] = {NULL, L"", L"text/plain", L"TEXT/PLAIN", L" text/plain ",
        L"application/vnd.example+json", L"*/*", L"text/*", L"text", L"text/", L"/plain",
        L"text /plain", L"text/plain; charset=utf-8", L"text/plain;charset=\"utf-8\"",
        L"text/plain; boundary=\"a;b\"", L"text/plain; charset=UTF-8; charset=utf-16",
        L"text/plain; name=value; q=0.5", L"text/plain; flag", L"text/plain; name=", L"text/plain;",
        L"text/plain; name=\"a\\\"b\"", L"text/plain; name=\"a\\\\b\"", L"text/plain; name=\"\"",
        L"text/plain; name=\"unterminated", L"text/plain\r\nX-Test: value", L"text/plain, text/html",
        L"text/plain; n\x00e4me=value", L"text/plain; name=\"\x00e9\"", L"text/plain\t;\tcharset\t=\tutf-8"};
    static const WCHAR *name_inputs[] = {NULL, L"", L"charset", L"charset=utf-8", L" charset = utf-8 ",
        L"charset=\"utf-8\"", L"name=", L"name=\"\"", L"name=\"a;b\"", L"name=bad value", L"bad name=x",
        L"name=\"a\\\"b\"", L"name=\"unterminated", L"name=x;other=y", L"name=x,other=y", L"x=value", L"foo=value", L"filename=value", L"filename*=value",
        L"boundary=value", L"type=value", L"NAME=value", L"q=value", L"name*=value"};
    const WCHAR *classes[] = {L"Windows.Web.Http.Headers.HttpMediaTypeHeaderValue",
            L"Windows.Web.Http.Headers.HttpNameValueHeaderValue"};
    const GUID *iids[] = {&media_factory_iid, &media_statics_iid, &name_factory_iid, &name_statics_iid};
    IInspectable *factories[4] = {NULL};
    HSTRING name;
    HRESULT hr;
    unsigned int i, failures = 0;

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr)) return 1;
    for (i = 0; i < ARRAYSIZE(factories); ++i)
    {
        name = string(classes[i / 2]);
        hr = RoGetActivationFactory(name, iids[i], (void **)&factories[i]);
        WindowsDeleteString(name);
        printf("{\"operation\":\"activation\",\"index\":%u,\"hr\":\"%08lx\"}\n", i, (unsigned long)hr);
        if (FAILED(hr) || !factories[i]) ++failures;
    }
    if (!failures)
    {
        for (i = 0; i < ARRAYSIZE(media_inputs); ++i)
        {
            test_parse(factories[0], 6, FALSE, TRUE, media_inputs[i], "media_create");
            test_parse(factories[1], 6, FALSE, TRUE, media_inputs[i], "media_parse");
            test_parse(factories[1], 7, TRUE, TRUE, media_inputs[i], "media_tryparse");
        }
        for (i = 0; i < ARRAYSIZE(name_inputs); ++i)
        {
            test_parse(factories[2], 6, FALSE, FALSE, name_inputs[i], "name_create");
            test_parse(factories[3], 6, FALSE, FALSE, name_inputs[i], "name_parse");
            test_parse(factories[3], 7, TRUE, FALSE, name_inputs[i], "name_tryparse");
        }
        test_mutations(factories[0], factories[2]);
        test_pair_values(factories[2]);
    }
    for (i = 0; i < ARRAYSIZE(factories); ++i)
        if (factories[i]) IInspectable_Release(factories[i]);
    RoUninitialize();
    return !!failures;
}
