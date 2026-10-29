#define main collector_main
#include "../native/debugger.c"
#undef main

static BOOL rejected(HANDLE handle, DWORD64 pc, DWORD64 sp, const char *expected)
{
    STACKFRAME64 stack = {0}, before;
    CONTEXT context = {0}, saved;
    const char *status;
    stack.AddrPC.Offset = pc; stack.AddrStack.Offset = sp;
    before = stack; saved = context;
    return !null_call_return(handle, &stack, &context, &status) &&
        ((!status && !expected) || (status && expected && !strcmp(status, expected))) &&
        !memcmp(&stack, &before, sizeof(stack)) && !memcmp(&context, &saved, sizeof(context));
}

int main(void)
{
    HANDLE handle = GetCurrentProcess();
    ULONG_PTR address = (ULONG_PTR)main;
    STACKFRAME64 stack = {0};
    CONTEXT context = {0};
    void *page;
    DWORD old;
    const char *status;
    if (!SymInitialize(handle, NULL, TRUE)) return 1;
    if (!rejected(handle, 1, (ULONG_PTR)&address, NULL) || !rejected(handle, 0, 1, "stack-unreadable") ||
        !rejected(NULL, 0, (ULONG_PTR)&address, "stack-unreadable")) return 2;
    address = 0;
    if (!rejected(handle, 0, (ULONG_PTR)&address, "stack-top-zero")) return 3;
    address = (ULONG_PTR)&address;
    if (!rejected(handle, 0, (ULONG_PTR)&address, "stack-top-not-executable")) return 4;
    page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return 5;
    *(ULONG_PTR *)page = (ULONG_PTR)main;
    if (!VirtualProtect(page, 4096, PAGE_NOACCESS, &old) ||
        !rejected(handle, 0, (ULONG_PTR)page, "stack-unreadable")) return 6;
    address = (ULONG_PTR)page;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old) ||
        !rejected(handle, 0, (ULONG_PTR)&address, "return-module-unavailable")) return 9;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old) ||
        !rejected(handle, 0, (ULONG_PTR)&address, "stack-top-not-executable")) return 10;
    VirtualFree(page, 0, MEM_RELEASE);
    page = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
    if (!page) return 11;
    address = (ULONG_PTR)page;
    if (!rejected(handle, 0, (ULONG_PTR)&address, "return-memory-unavailable")) return 12;
    VirtualFree(page, 0, MEM_RELEASE);
    address = (ULONG_PTR)main;
    stack.AddrStack.Offset = (ULONG_PTR)&address;
#ifdef _WIN64
    context.Rsp = stack.AddrStack.Offset;
#else
    context.Esp = stack.AddrStack.Offset;
#endif
    if (!null_call_return(handle, &stack, &context, &status) || strcmp(status, "recovered") || stack.AddrPC.Offset != address ||
        stack.AddrStack.Offset != (ULONG_PTR)&address + sizeof(address)) return 7;
#ifdef _WIN64
    if (context.Rip != address || context.Rsp != stack.AddrStack.Offset) return 8;
#else
    if (context.Eip != address || context.Esp != stack.AddrStack.Offset) return 8;
#endif
    SymCleanup(handle);
    puts("null call return controls passed");
    return 0;
}
