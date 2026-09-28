#define COBJMACROS
#include <windows.h>
#include <roapi.h>
#include <winstring.h>

#include <stdio.h>

static const GUID iid_core_application =
    {0x0aacf7a4, 0x5e1d, 0x49df, {0x80, 0x34, 0xfb, 0x6a, 0x68, 0xbc, 0x5e, 0xd1}};
static const GUID iid_activation_factory =
    {0x00000035, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID iid_protection_policy_manager_statics2 =
    {0xb68f9a8c, 0x39e0, 0x4649, {0xb2, 0xe4, 0x07, 0x0a, 0xb8, 0xa5, 0x79, 0xb3}};

static int check_factory(const WCHAR *class_name, const GUID *iid, const char *label)
{
    IUnknown *factory = NULL;
    HSTRING class_id;
    HRESULT hr;

    hr = WindowsCreateString(class_name, wcslen(class_name), &class_id);
    if (FAILED(hr))
    {
        printf("%s:string:%08lx\n", label, (unsigned long)hr);
        return 1;
    }

    hr = RoGetActivationFactory(class_id, iid, (void **)&factory);
    WindowsDeleteString(class_id);
    printf("%s:%08lx\n", label, (unsigned long)hr);
    if (FAILED(hr)) return 1;

    IUnknown_Release(factory);
    return 0;
}

int main(void)
{
    int failures = 0;
    HRESULT hr;

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("ro_initialize:%08lx\n", (unsigned long)hr);
        return 1;
    }

    failures += check_factory(L"Windows.ApplicationModel.Core.CoreApplication",
            &iid_core_application, "core_application");
    failures += check_factory(L"Windows.Networking.Sockets.MessageWebSocket",
            &iid_activation_factory, "message_websocket");
    failures += check_factory(L"Windows.Security.EnterpriseData.ProtectionPolicyManager",
            &iid_protection_policy_manager_statics2, "protection_policy");

    RoUninitialize();
    return failures != 0;
}
