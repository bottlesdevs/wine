#include <windows.h>
#include <stdio.h>

int main(void)
{
    static const WCHAR path[] = L"C:\\soda-file-security-smoke.tmp";
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    PSID owner = NULL, authenticated = NULL;
    PACL dacl = NULL;
    HANDLE file = NULL;
    DWORD dacl_size;
    int ret = 1;

    if (!AllocateAndInitializeSid(&nt_authority, 5, SECURITY_NT_NON_UNIQUE,
                                  0x11111111, 0x22222222, 1000, 1000,
                                  0, 0, 0, &owner) ||
        !AllocateAndInitializeSid(&nt_authority, 1, SECURITY_AUTHENTICATED_USER_RID,
                                  0, 0, 0, 0, 0, 0, 0, &authenticated))
    {
        printf("sid:%lu\n", GetLastError());
        goto done;
    }

    dacl_size = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) +
                GetLengthSid(authenticated);
    dacl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dacl_size);
    if (!dacl || !InitializeAcl(dacl, dacl_size, ACL_REVISION) ||
        !AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, authenticated) ||
        !InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&sd, owner, FALSE) ||
        !SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE))
    {
        printf("descriptor:%lu\n", GetLastError());
        goto done;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    DeleteFileW(path);
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("create:%lu\n", GetLastError());
        file = NULL;
        goto done;
    }

    CloseHandle(file);
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("reopen:%lu\n", GetLastError());
        file = NULL;
        goto done;
    }

    puts("reopen:ok");
    ret = 0;

done:
    if (file) CloseHandle(file);
    DeleteFileW(path);
    HeapFree(GetProcessHeap(), 0, dacl);
    if (authenticated) FreeSid(authenticated);
    if (owner) FreeSid(owner);
    return ret;
}
