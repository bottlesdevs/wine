#include <windows.h>
#include <stdio.h>

int main(void)
{
    static WCHAR *hosts[] =
    {
        NULL, L"", L"   ", L"localhost", L"localhost ", L"localhost  ",
        L" one.invalid\t two.invalid  ", L"ldap://one.invalid:123 two.invalid"
    };
    HMODULE module = LoadLibraryW(L"wldap32.dll");
    void *(CDECL *init)(WCHAR *, ULONG);
    ULONG (CDECL *unbind)(void *);
    unsigned i, repeat, failures = 0;

    if (!module) return 2;
    init = (void *)GetProcAddress(module, "ldap_initW");
    unbind = (void *)GetProcAddress(module, "ldap_unbind");
    if (!init || !unbind) return 3;

    for (repeat = 0; repeat < 128; repeat++)
    {
        for (i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++)
        {
            void *context = init(hosts[i], repeat % 2 ? 389 : 3268);
            if (!context)
            {
                printf("ldap_init:%u:%lu\n", i, GetLastError());
                failures++;
            }
            else if (unbind(context)) failures++;
        }
    }
    FreeLibrary(module);
    printf("ldap_init_checks:1024 failures:%u\n", failures);
    return failures != 0;
}
