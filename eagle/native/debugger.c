#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PROCESSES 64
#define MAX_THREADS 1024
#define MAX_BREAKPOINTS 128

struct process { DWORD id; HANDLE handle; BOOL initial_break, pause_requested; char stop_module[260]; };
struct thread { DWORD id, pid; HANDLE handle; DWORD64 rearm, original_dr[6]; BOOL stepping, suspended, saved_dr, saved_tf, original_tf; };
struct breakpoint { DWORD pid; DWORD64 address; BYTE original; BOOL armed, logpoint; char reg[16]; unsigned comparison; DWORD64 value, hits; };
struct watchpoint { DWORD pid; DWORD64 address; unsigned length, mode; };
static struct process processes[MAX_PROCESSES];
static struct thread threads[MAX_THREADS];
static struct breakpoint breakpoints[MAX_BREAKPOINTS];
static struct watchpoint watchpoints[4];
static CRITICAL_SECTION command_lock;
static char commands[64][1024];
static unsigned command_read, command_write;
static volatile LONG input_closed;
static volatile LONG dropped_commands;
static unsigned long long sequence;
static BOOL interactive;

static BOOL wine_console_host(CREATE_PROCESS_DEBUG_INFO *info, const char *path)
{
    char directory[32768], marker[sizeof("Wine builtin DLL")];
    DWORD size;
    SIZE_T copied;
    const char *option = getenv("EAGLE_TRACE_EXCLUDE_WINE_CONHOST");
    if (!option || strcmp(option, "1")) return FALSE;
    size = GetSystemDirectoryA(directory, sizeof(directory));
    if (!size || size >= sizeof(directory)) return FALSE;
    while (*path == '\\' || *path == '?') path++;
    if (_strnicmp(path, directory, size) || _stricmp(path + size, "\\conhost.exe")) return FALSE;
    return ReadProcessMemory(info->hProcess, (const char *)info->lpBaseOfImage + 64,
                             marker, sizeof(marker), &copied) && copied == sizeof(marker) &&
           !memcmp(marker, "Wine builtin DLL", sizeof(marker));
}

static BOOL register_value(const CONTEXT *context, const char *name, DWORD64 *value)
{
#ifdef _WIN64
#define REGISTER(short_name, full_name, member) if (!strcmp(name, short_name) || !strcmp(name, full_name)) { *value = context->member; return TRUE; }
    REGISTER("ax", "rax", Rax) REGISTER("bx", "rbx", Rbx)
    REGISTER("cx", "rcx", Rcx) REGISTER("dx", "rdx", Rdx)
    REGISTER("sp", "rsp", Rsp) REGISTER("bp", "rbp", Rbp)
    REGISTER("ip", "rip", Rip) REGISTER("si", "rsi", Rsi)
    REGISTER("di", "rdi", Rdi)
    REGISTER("r8", "r8", R8) REGISTER("r9", "r9", R9)
#else
#define REGISTER(short_name, full_name, member) if (!strcmp(name, short_name) || !strcmp(name, full_name)) { *value = context->member; return TRUE; }
    REGISTER("ax", "eax", Eax) REGISTER("bx", "ebx", Ebx)
    REGISTER("cx", "ecx", Ecx) REGISTER("dx", "edx", Edx)
    REGISTER("sp", "esp", Esp) REGISTER("bp", "ebp", Ebp)
    REGISTER("ip", "eip", Eip) REGISTER("si", "esi", Esi)
    REGISTER("di", "edi", Edi)
#endif
#undef REGISTER
    if (!strcmp(name, "flags")) { *value = context->EFlags; return TRUE; }
    return FALSE;
}

static BOOL condition_matches(struct breakpoint *point, const CONTEXT *context)
{
    DWORD64 value;
    if (!point->comparison) return TRUE;
    if (!strcmp(point->reg, "hits")) value = point->hits;
    else if (!register_value(context, point->reg, &value)) return FALSE;
    switch (point->comparison)
    {
        case 1: return value == point->value;
        case 2: return value != point->value;
        case 3: return value < point->value;
        case 4: return value <= point->value;
        case 5: return value > point->value;
        case 6: return value >= point->value;
    }
    return FALSE;
}

static void string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; p++)
    {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void event(const char *kind, DWORD pid, DWORD tid)
{
    printf("{\"seq\":%llu,\"time_ms\":%llu,\"kind\":", ++sequence, GetTickCount64());
    string(kind);
    printf(",\"pid\":%lu,\"tid\":%lu", pid, tid);
}

static void end_event(void) { puts("}"); fflush(stdout); }

static void error(const char *operation, DWORD code)
{
    event("error", 0, 0);
    printf(",\"operation\":"); string(operation);
    printf(",\"winerror\":%lu", code); end_event();
}

static struct process *process(DWORD pid)
{
    unsigned i;
    for (i = 0; i < MAX_PROCESSES; i++) if (processes[i].id == pid) return processes + i;
    return NULL;
}

static void resume_siblings(DWORD pid)
{
    unsigned i;
    for (i = 0; i < MAX_THREADS; i++) if (threads[i].pid == pid && threads[i].id && threads[i].suspended)
    {
        if (ResumeThread(threads[i].handle) == (DWORD)-1) error("resume_thread", GetLastError());
        else threads[i].suspended = FALSE;
    }
}

static void suspend_siblings(DWORD pid, DWORD tid)
{
    unsigned i;
    for (i = 0; i < MAX_THREADS; i++) if (threads[i].pid == pid && threads[i].id && threads[i].id != tid && !threads[i].suspended)
    {
        if (SuspendThread(threads[i].handle) == (DWORD)-1) error("suspend_thread", GetLastError());
        else threads[i].suspended = TRUE;
    }
}

static void apply_watches(struct thread *thread, BOOL clear)
{
    CONTEXT context;
    DWORD64 control = 0, values[4] = {0};
    unsigned i;
    if (clear && !thread->saved_dr) return;
    memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread->handle, &context)) { error("watch_context", GetLastError()); return; }
    if (clear)
    {
        context.Dr0 = thread->original_dr[0]; context.Dr1 = thread->original_dr[1];
        context.Dr2 = thread->original_dr[2]; context.Dr3 = thread->original_dr[3];
        context.Dr6 = thread->original_dr[4]; context.Dr7 = thread->original_dr[5];
        if (!SetThreadContext(thread->handle, &context)) error("watch_restore", GetLastError());
        else thread->saved_dr = FALSE;
        return;
    }
    if (!thread->saved_dr)
    {
        thread->original_dr[0] = context.Dr0; thread->original_dr[1] = context.Dr1;
        thread->original_dr[2] = context.Dr2; thread->original_dr[3] = context.Dr3;
        thread->original_dr[4] = context.Dr6; thread->original_dr[5] = context.Dr7;
        thread->saved_dr = TRUE;
    }
    for (i = 0; i < 4; i++) if (!clear && watchpoints[i].pid == thread->pid && watchpoints[i].address)
    {
        unsigned length = watchpoints[i].length;
        unsigned encoded = length == 1 ? 0 : length == 2 ? 1 : length == 4 ? 3 : 2;
        values[i] = watchpoints[i].address;
        control |= (DWORD64)1 << (2 * i);
        control |= (DWORD64)(watchpoints[i].mode | (encoded << 2)) << (16 + 4 * i);
    }
    context.Dr0 = values[0]; context.Dr1 = values[1]; context.Dr2 = values[2]; context.Dr3 = values[3];
    context.Dr6 = 0; context.Dr7 = control;
    if (!SetThreadContext(thread->handle, &context)) error("watch_context", GetLastError());
}

static void add_thread(DWORD pid, DWORD tid, HANDLE handle)
{
    unsigned i, watch, pending;
    for (i = 0; i < MAX_THREADS; i++) if (!threads[i].id)
    {
        threads[i] = (struct thread){.id = tid, .pid = pid, .handle = handle};
        for (pending = 0; pending < MAX_THREADS; pending++) if (threads[pending].pid == pid && threads[pending].rearm)
        {
            if (SuspendThread(handle) == (DWORD)-1) error("suspend_thread", GetLastError());
            else threads[i].suspended = TRUE;
            break;
        }
        for (watch = 0; watch < 4; watch++) if (watchpoints[watch].pid == pid && watchpoints[watch].address)
        {
            apply_watches(threads + i, FALSE);
            break;
        }
        return;
    }
    CloseHandle(handle);
    error("thread_capacity", ERROR_NOT_ENOUGH_MEMORY);
}

struct frame_info
{
    HANDLE handle;
    DWORD64 address, displacement;
    IMAGEHLP_MODULE64 module;
    char symbol[1024], file[4096];
    DWORD line;
    BOOL has_module, has_symbol, has_line;
};
static struct frame_info frame_cache[256];
static unsigned frame_next;

static void invalidate_frames(void)
{
    memset(frame_cache, 0, sizeof(frame_cache));
    frame_next = 0;
}

static void frame(HANDLE handle, DWORD64 address)
{
    struct frame_info *cached = NULL;
    unsigned i;
    for (i = 0; i < 256; i++) if (frame_cache[i].handle == handle && frame_cache[i].address == address)
    {
        cached = frame_cache + i;
        break;
    }
    if (!cached)
    {
        char storage[sizeof(SYMBOL_INFO) + 1024];
        SYMBOL_INFO *symbol = (SYMBOL_INFO *)storage;
        IMAGEHLP_LINE64 line;
        DWORD line_offset = 0;
        cached = frame_cache + frame_next++ % 256;
        memset(cached, 0, sizeof(*cached));
        cached->handle = handle; cached->address = address;
        cached->module.SizeOfStruct = sizeof(cached->module);
        memset(storage, 0, sizeof(storage));
        symbol->SizeOfStruct = sizeof(*symbol); symbol->MaxNameLen = 1023;
        cached->has_symbol = SymFromAddr(handle, address, &cached->displacement, symbol);
        if (cached->has_symbol) snprintf(cached->symbol, sizeof(cached->symbol), "%.*s", (int)sizeof(cached->symbol) - 1, symbol->Name);
        memset(&line, 0, sizeof(line)); line.SizeOfStruct = sizeof(line);
        cached->has_line = SymGetLineFromAddr64(handle, address, &line_offset, &line);
        if (cached->has_line)
        {
            snprintf(cached->file, sizeof(cached->file), "%.*s", (int)sizeof(cached->file) - 1, line.FileName);
            cached->line = line.LineNumber;
        }
        cached->has_module = SymGetModuleInfo64(handle, address, &cached->module);
    }
    printf("{\"address\":\"0x%llx\"", address);
    if (cached->has_module)
    {
        printf(",\"module\":"); string(cached->module.ModuleName);
        printf(",\"rva\":\"0x%llx\",\"symbol_type\":%u", address - cached->module.BaseOfImage, cached->module.SymType);
        printf(",\"image\":"); string(cached->module.ImageName);
        if (cached->module.SymType == SymPdb)
        {
            printf(",\"loaded_pdb\":"); string(cached->module.LoadedPdbName);
            printf(",\"pdb_unmatched\":%s", cached->module.PdbUnmatched ? "true" : "false");
        }
    }
    if (cached->has_symbol)
    {
        printf(",\"symbol\":"); string(cached->symbol);
        printf(",\"displacement\":%llu", cached->displacement);
    }
    else printf(",\"symbol\":null");
    if (cached->has_line)
    {
        printf(",\"file\":"); string(cached->file);
        printf(",\"line\":%lu", cached->line);
    }
    putchar('}');
}

static void snapshot(DWORD pid, DWORD tid)
{
    struct process *p = process(pid);
    unsigned i;
    if (!p) { error("snapshot", ERROR_INVALID_PARAMETER); return; }
    for (i = 0; i < MAX_THREADS; i++) if (threads[i].pid == pid && threads[i].id && (!tid || threads[i].id == tid))
    {
        CONTEXT context;
        STACKFRAME64 stack;
        DWORD machine;
        unsigned depth;
        memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(threads[i].handle, &context)) { error("context", GetLastError()); continue; }
        memset(&stack, 0, sizeof(stack));
#ifdef _WIN64
        machine = IMAGE_FILE_MACHINE_AMD64;
        stack.AddrPC.Offset = context.Rip; stack.AddrFrame.Offset = context.Rbp; stack.AddrStack.Offset = context.Rsp;
#else
        machine = IMAGE_FILE_MACHINE_I386;
        stack.AddrPC.Offset = context.Eip; stack.AddrFrame.Offset = context.Ebp; stack.AddrStack.Offset = context.Esp;
#endif
        stack.AddrPC.Mode = stack.AddrFrame.Mode = stack.AddrStack.Mode = AddrModeFlat;
        event("snapshot", pid, threads[i].id);
#ifdef _WIN64
        printf(",\"registers\":{\"ip\":\"0x%llx\",\"sp\":\"0x%llx\",\"bp\":\"0x%llx\",\"ax\":\"0x%llx\",\"bx\":\"0x%llx\",\"cx\":\"0x%llx\",\"dx\":\"0x%llx\",\"flags\":%lu}", context.Rip, context.Rsp, context.Rbp, context.Rax, context.Rbx, context.Rcx, context.Rdx, context.EFlags);
#else
        printf(",\"registers\":{\"ip\":\"0x%lx\",\"sp\":\"0x%lx\",\"bp\":\"0x%lx\",\"ax\":\"0x%lx\",\"bx\":\"0x%lx\",\"cx\":\"0x%lx\",\"dx\":\"0x%lx\",\"flags\":%lu}", context.Eip, context.Esp, context.Ebp, context.Eax, context.Ebx, context.Ecx, context.Edx, context.EFlags);
#endif
        printf(",\"frames\":["); frame(p->handle, stack.AddrPC.Offset);
        for (depth = 1; depth < 128; depth++)
        {
            DWORD64 previous = stack.AddrPC.Offset;
            if (!StackWalk64(machine, p->handle, threads[i].handle, &stack, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) break;
            if (!stack.AddrPC.Offset) break;
            if (previous == stack.AddrPC.Offset)
            {
                if (depth == 1) continue;
                break;
            }
            putchar(','); frame(p->handle, stack.AddrPC.Offset);
        }
        printf("],\"unwind\":\"dbghelp\",\"truncated\":%s", depth == 128 ? "true" : "false");
        end_event();
    }
    event("snapshot_complete", pid, tid); printf(",\"scope\":\"%s\"", tid ? "thread" : "process"); end_event();
}

static void dump(DWORD pid, DWORD tid, EXCEPTION_RECORD *record)
{
    char name[64];
    struct process *p = process(pid);
    HANDLE file;
    MINIDUMP_EXCEPTION_INFORMATION info;
    EXCEPTION_POINTERS pointers;
    CONTEXT context;
    unsigned i;
    if (!p) return;
    snprintf(name, sizeof(name), "process-%lu-%llu.dmp", pid, sequence);
    file = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { error("dump_open", GetLastError()); return; }
    memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_FULL;
    for (i = 0; i < MAX_THREADS; i++) if (threads[i].id == tid && threads[i].pid == pid) GetThreadContext(threads[i].handle, &context);
    pointers.ExceptionRecord = record; pointers.ContextRecord = &context;
    info.ThreadId = tid; info.ExceptionPointers = &pointers; info.ClientPointers = FALSE;
    if (MiniDumpWriteDump(p->handle, pid, file, MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules, record ? &info : NULL, NULL, NULL))
    {
        event("dump", pid, tid); printf(",\"path\":"); string(name); end_event();
    }
    else error("dump", GetLastError());
    CloseHandle(file);
}

static BOOL write_byte(struct process *p, DWORD64 address, BYTE value)
{
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(p->handle, (void *)(uintptr_t)address, &value, 1, &written);
    if (ok && written == 1) FlushInstructionCache(p->handle, (void *)(uintptr_t)address, 1);
    else { error("breakpoint_write", GetLastError()); return FALSE; }
    return TRUE;
}

static BOOL set_breakpoint(DWORD pid, const char *name)
{
    struct process *p = process(pid);
    char storage[sizeof(SYMBOL_INFO) + 1024];
    SYMBOL_INFO *symbol = (SYMBOL_INFO *)storage;
    DWORD64 address;
    char *end;
    unsigned i;
    SIZE_T count;
    if (!p) { error("breakpoint_process", ERROR_INVALID_PARAMETER); return FALSE; }
    address = strtoull(name, &end, 0);
    if (*end || !address)
    {
        memset(storage, 0, sizeof(storage)); symbol->SizeOfStruct = sizeof(*symbol); symbol->MaxNameLen = 1023;
        if (!SymFromName(p->handle, name, symbol)) { error("breakpoint_symbol", GetLastError()); return FALSE; }
        address = symbol->Address;
    }
    for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == pid && breakpoints[i].address == address)
    {
        event("breakpoint_set", pid, 0); printf(",\"address\":\"0x%llx\",\"name\":", address); string(name); end_event(); return TRUE;
    }
    for (i = 0; i < MAX_BREAKPOINTS; i++) if (!breakpoints[i].address)
    {
        BYTE original;
        BOOL rearming = FALSE;
        unsigned t;
        if (!ReadProcessMemory(p->handle, (void *)(uintptr_t)address, &original, 1, &count) || count != 1) { error("breakpoint_read", GetLastError()); return FALSE; }
        if (original == 0xcc) { error("breakpoint_existing_trap", ERROR_INVALID_PARAMETER); return FALSE; }
        for (t = 0; t < MAX_THREADS; t++) if (threads[t].pid == pid && threads[t].rearm == address) rearming = TRUE;
        if (!rearming && !write_byte(p, address, 0xcc)) return FALSE;
        breakpoints[i].pid = pid; breakpoints[i].address = address;
        breakpoints[i].original = original; breakpoints[i].armed = !rearming;
        event("breakpoint_set", pid, 0); printf(",\"address\":\"0x%llx\",\"name\":", address); string(name); end_event();
        return TRUE;
    }
    error("breakpoint_capacity", ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
}

static BOOL remove_breakpoint(DWORD pid, DWORD64 address)
{
    unsigned i;
    for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == pid && breakpoints[i].address == address)
    {
        if (breakpoints[i].armed && !write_byte(process(pid), address, breakpoints[i].original)) return FALSE;
        memset(breakpoints + i, 0, sizeof(breakpoints[i]));
        event("breakpoint_removed", pid, 0); printf(",\"address\":\"0x%llx\"", address); end_event(); return TRUE;
    }
    error("breakpoint_remove", ERROR_NOT_FOUND); return FALSE;
}

struct source_query { DWORD pid, line; const char *file; DWORD64 addresses[32]; unsigned count, examined; BOOL overflow; };

static BOOL CALLBACK source_line(SRCCODEINFO *line, void *user)
{
    struct source_query *query = user;
    char path[sizeof(line->FileName)], wanted[MAX_PATH];
    const char *name, *target;
    unsigned i;
    if (++query->examined > 1000000) { query->overflow = TRUE; return FALSE; }
    if (line->LineNumber != query->line) return TRUE;
    memcpy(path, line->FileName, sizeof(path)); path[sizeof(path) - 1] = 0;
    snprintf(wanted, sizeof(wanted), "%s", query->file);
    for (i = 0; path[i]; i++) if (path[i] == '\\') path[i] = '/';
    for (i = 0; wanted[i]; i++) if (wanted[i] == '\\') wanted[i] = '/';
    name = path; target = wanted;
    if (!strchr(wanted, '/')) { const char *base = strrchr(path, '/'); if (base) name = base + 1; }
    else if (wanted[0] == '/' && (path[0] == 'z' || path[0] == 'Z') && path[1] == ':') name = path + 2;
    if (_stricmp(name, target)) return TRUE;
    for (i = 0; i < query->count; i++) if (query->addresses[i] == line->Address) return TRUE;
    if (query->count == 32) { query->overflow = TRUE; return FALSE; }
    query->addresses[query->count++] = line->Address;
    return TRUE;
}

static BOOL CALLBACK source_module(const char *name, DWORD64 base, void *user)
{
    struct source_query *query = user;
    struct process *p = process(query->pid);
    (void)name;
    SymEnumLines(p->handle, base, NULL, NULL, source_line, query);
    return !query->overflow;
}

static void source_breakpoint(DWORD pid, const char *argument)
{
    struct source_query query = {.pid = pid};
    const char *separator = strrchr(argument, ' ');
    char file[MAX_PATH], *end;
    unsigned i, slot;
    BOOL existing[32] = {0};
    if (!separator || separator == argument || separator - argument >= (int)sizeof(file)) { error("source_breakpoint", ERROR_INVALID_PARAMETER); return; }
    memcpy(file, argument, separator - argument); file[separator - argument] = 0;
    query.line = strtoul(separator + 1, &end, 10); query.file = file;
    if (*end || !query.line || !process(pid)) { error("source_breakpoint", ERROR_INVALID_PARAMETER); return; }
    SymEnumerateModules64(process(pid)->handle, source_module, &query);
    if (query.overflow || !query.count) { error("source_lines", query.overflow ? ERROR_NOT_ENOUGH_MEMORY : ERROR_NOT_FOUND); return; }
    for (i = 0; i < query.count; i++) for (slot = 0; slot < MAX_BREAKPOINTS; slot++)
        if (breakpoints[slot].pid == pid && breakpoints[slot].address == query.addresses[i]) existing[i] = TRUE;
    for (i = 0; i < query.count; i++)
    {
        char address[32]; snprintf(address, sizeof(address), "0x%llx", query.addresses[i]);
        if (!set_breakpoint(pid, address))
        {
            while (i--) if (!existing[i]) remove_breakpoint(pid, query.addresses[i]);
            return;
        }
    }
    event("source_breakpoint_set", pid, 0); printf(",\"file\":"); string(file);
    printf(",\"line\":%lu,\"addresses\":[", query.line);
    for (i = 0; i < query.count; i++) printf("%s\"0x%llx\"", i ? "," : "", query.addresses[i]);
    putchar(']'); end_event();
}

static DWORD WINAPI read_commands(void *unused)
{
    char line[1024];
    (void)unused;
    while (fgets(line, sizeof(line), stdin))
    {
        line[strcspn(line, "\r\n")] = 0;
        EnterCriticalSection(&command_lock);
        if (command_write - command_read < 64)
        {
            strcpy(commands[command_write % 64], line);
            command_write++;
        }
        else InterlockedIncrement(&dropped_commands);
        LeaveCriticalSection(&command_lock);
    }
    InterlockedExchange(&input_closed, 1);
    return 0;
}

static BOOL next_command(char *line)
{
    BOOL found = FALSE;
    LONG dropped = InterlockedExchange(&dropped_commands, 0);
    if (dropped) { event("commands_dropped", 0, 0); printf(",\"count\":%ld", dropped); end_event(); }
    EnterCriticalSection(&command_lock);
    if (command_read != command_write)
    {
        strcpy(line, commands[command_read % 64]); command_read++; found = TRUE;
    }
    LeaveCriticalSection(&command_lock);
    return found;
}

static void detach_all(void)
{
    unsigned i;
    for (i = 0; i < MAX_THREADS; i++) if (threads[i].id)
    {
        CONTEXT context;
        apply_watches(threads + i, TRUE);
        memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_CONTROL;
        if ((threads[i].rearm || threads[i].stepping) && GetThreadContext(threads[i].handle, &context))
        {
            context.EFlags = (context.EFlags & ~0x100) | (threads[i].original_tf ? 0x100 : 0);
            SetThreadContext(threads[i].handle, &context);
        }
    }
    for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].armed)
    {
        struct process *p = process(breakpoints[i].pid);
        if (p) write_byte(p, breakpoints[i].address, breakpoints[i].original);
    }
    for (i = 0; i < MAX_PROCESSES; i++) if (processes[i].id)
    {
        DWORD id = processes[i].id;
        resume_siblings(id);
        if (!DebugActiveProcessStop(id)) error("detach", GetLastError());
        else { event("detached", id, 0); end_event(); }
    }
}

static int command(const char *line, DEBUG_EVENT *pending, DWORD *status)
{
    unsigned i;
    DWORD pid = pending ? pending->dwProcessId : 0;
    if (!strcmp(line, "detach")) { detach_all(); return 2; }
    if (!strcmp(line, "pause"))
    {
        if (pending) return 0;
        for (i = 0; i < MAX_PROCESSES; i++) if (processes[i].id)
        {
            processes[i].pause_requested = TRUE;
            if (!DebugBreakProcess(processes[i].handle)) { processes[i].pause_requested = FALSE; error("pause", GetLastError()); }
        }
        return 0;
    }
    if (!pending) { error("requires_stop", ERROR_BUSY); return 0; }
    if (!strcmp(line, "continue")) return 1;
    if (!strcmp(line, "pass")) { *status = DBG_EXCEPTION_NOT_HANDLED; return 1; }
    if (!strcmp(line, "snapshot")) { snapshot(pid, 0); return 0; }
    if (!strcmp(line, "dump")) { dump(pid, pending->dwThreadId, NULL); return 0; }
    if (!strcmp(line, "clear"))
    {
        struct process *p = process(pid);
        for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == pid)
        {
            if (breakpoints[i].armed) write_byte(p, breakpoints[i].address, breakpoints[i].original);
            memset(breakpoints + i, 0, sizeof(breakpoints[i]));
        }
        event("breakpoints_cleared", pid, 0); end_event(); return 0;
    }
    if (!strncmp(line, "watch ", 6))
    {
        unsigned long long address;
        unsigned length;
        char mode[16];
        unsigned t;
        if (sscanf(line + 6, "%llx %u %15s", &address, &length, mode) != 3 || !address || (length != 1 && length != 2 && length != 4 && !(sizeof(void *) == 8 && length == 8)) || address % length || (strcmp(mode, "write") && strcmp(mode, "access")))
        { error("watch_bounds", ERROR_INVALID_PARAMETER); return 0; }
        for (i = 0; i < 4; i++) if (!watchpoints[i].address) break;
        if (i == 4) { error("watch_capacity", ERROR_NOT_ENOUGH_MEMORY); return 0; }
        watchpoints[i] = (struct watchpoint){pid, address, length, !strcmp(mode, "write") ? 1 : 3};
        for (t = 0; t < MAX_THREADS; t++) if (threads[t].pid == pid && threads[t].id) apply_watches(threads + t, FALSE);
        event("watchpoint_set", pid, 0); printf(",\"slot\":%u,\"address\":\"0x%llx\"", i, address); end_event();
        return 0;
    }
    if (!strncmp(line, "break ", 6)) { set_breakpoint(pid, line + 6); return 0; }
    if (!strncmp(line, "remove ", 7))
    {
        char *end;
        DWORD64 address = strtoull(line + 7, &end, 0);
        if (*end || !address) error("breakpoint_remove", ERROR_INVALID_PARAMETER);
        else remove_breakpoint(pid, address);
        return 0;
    }
    if (!strncmp(line, "source ", 7)) { source_breakpoint(pid, line + 7); return 0; }
    if (!strncmp(line, "module ", 7))
    {
        struct process *p = process(pid);
        const char *name = line + 7;
        if (!*name || strlen(name) >= sizeof(p->stop_module) || strpbrk(name, "/\\")) { error("module_breakpoint", ERROR_INVALID_PARAMETER); return 0; }
        strcpy(p->stop_module, name);
        event("module_breakpoint_set", pid, 0); printf(",\"name\":"); string(name); end_event(); return 0;
    }
    if (!strncmp(line, "condition ", 10) || !strncmp(line, "logpoint ", 9))
    {
        BOOL logging = !strncmp(line, "logpoint ", 9);
        unsigned long long address, value = 0;
        char reg[16], op[4], extra;
        unsigned comparison = 0;
        CONTEXT context = {0}; DWORD64 unused;
        const char *operators[] = {"", "==", "!=", "<", "<=", ">", ">="};
        if (logging)
        {
            if (sscanf(line + 9, "%llx %c", &address, &extra) != 1) { error("logpoint", ERROR_INVALID_PARAMETER); return 0; }
        }
        else
        {
            if (sscanf(line + 10, "%llx %15s %3s %llx %c", &address, reg, op, &value, &extra) != 4 || (strcmp(reg, "hits") && !register_value(&context, reg, &unused)))
            { error("condition", ERROR_INVALID_PARAMETER); return 0; }
            for (comparison = 1; comparison <= 6; comparison++) if (!strcmp(operators[comparison], op)) break;
            if (comparison > 6) { error("condition", ERROR_INVALID_PARAMETER); return 0; }
        }
        for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == pid && breakpoints[i].address == address) break;
        if (i == MAX_BREAKPOINTS) { error("condition_breakpoint", ERROR_NOT_FOUND); return 0; }
        if (logging) breakpoints[i].logpoint = TRUE;
        else { strcpy(breakpoints[i].reg, reg); breakpoints[i].comparison = comparison; breakpoints[i].value = value; }
        event(logging ? "logpoint_set" : "condition_set", pid, 0); printf(",\"address\":\"0x%llx\"", address); end_event(); return 0;
    }
    if (!strcmp(line, "step"))
    {
        for (i = 0; i < MAX_THREADS; i++) if (threads[i].id == pending->dwThreadId && threads[i].pid == pid)
        {
            CONTEXT context; memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(threads[i].handle, &context)) { error("step_context", GetLastError()); return 0; }
            if (!threads[i].saved_tf) { threads[i].original_tf = !!(context.EFlags & 0x100); threads[i].saved_tf = TRUE; }
            context.EFlags |= 0x100;
            if (!SetThreadContext(threads[i].handle, &context)) { error("step_context", GetLastError()); return 0; }
            threads[i].stepping = TRUE; return 1;
        }
    }
    if (!strncmp(line, "memory ", 7))
    {
        unsigned long long address;
        unsigned size;
        BYTE bytes[4096]; SIZE_T read;
        struct process *p = process(pid);
        if (sscanf(line + 7, "%llx %u", &address, &size) != 2 || !size || size > sizeof(bytes)) { error("memory_bounds", ERROR_INVALID_PARAMETER); return 0; }
        if (!ReadProcessMemory(p->handle, (void *)(uintptr_t)address, bytes, size, &read)) { error("memory", GetLastError()); return 0; }
        event("memory", pid, 0); printf(",\"address\":\"0x%llx\",\"hex\":\"", address);
        for (i = 0; i < read; i++) printf("%02x", bytes[i]);
        printf("\""); end_event(); return 0;
    }
    error("unknown_command", ERROR_INVALID_PARAMETER);
    return 0;
}

static int stopped(DEBUG_EVENT *debug, DWORD *status, const char *reason)
{
    int action = 0;
    char line[1024];
    event("stopped", debug->dwProcessId, debug->dwThreadId); printf(",\"reason\":"); string(reason); end_event();
    while (!action)
    {
        if (next_command(line)) action = command(line, debug, status);
        else if (InterlockedCompareExchange(&input_closed, 0, 0)) { detach_all(); return 2; }
        else Sleep(10);
    }
    return action;
}

int main(int argc, char **argv)
{
    DEBUG_EVENT debug;
    DWORD active = 0, status, primary_pid = 0;
    unsigned i;
    char line[1024];
    if (argc < 3) { fputs("usage: eagle-debug.exe run <command-line> [interactive] | attach <pid> [interactive]\n", stderr); return 2; }
    interactive = argc > 3 && !strcmp(argv[3], "interactive");
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_EXACT_SYMBOLS | SYMOPT_FAIL_CRITICAL_ERRORS);
    InitializeCriticalSection(&command_lock);
    CloseHandle(CreateThread(NULL, 0, read_commands, NULL, 0, NULL));
    if (!strcmp(argv[1], "run"))
    {
        STARTUPINFOA startup; PROCESS_INFORMATION info;
        SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
        HANDLE output;
        BOOL launched;
        DWORD launch_error;
        char *target = _strdup(argv[2]);
        memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
        output = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
        if (output == INVALID_HANDLE_VALUE) { error("target_output", GetLastError()); free(target); return 1; }
        SetHandleInformation(GetStdHandle(STD_INPUT_HANDLE), HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(GetStdHandle(STD_OUTPUT_HANDLE), HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(GetStdHandle(STD_ERROR_HANDLE), HANDLE_FLAG_INHERIT, 0);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = startup.hStdOutput = startup.hStdError = output;
        launched = CreateProcessA(NULL, target, NULL, NULL, TRUE, DEBUG_PROCESS, NULL, getenv("EAGLE_TARGET_CWD"), &startup, &info);
        launch_error = GetLastError(); CloseHandle(output);
        if (!launched) { error("launch", launch_error); free(target); return 1; }
        primary_pid = info.dwProcessId;
        CloseHandle(info.hThread); CloseHandle(info.hProcess); free(target);
    }
    else if (!strcmp(argv[1], "attach"))
    {
        char *end; unsigned long id = strtoul(argv[2], &end, 0);
        if (*end || !id || !DebugActiveProcess(id)) { error("attach", GetLastError()); return 1; }
        primary_pid = id;
    }
    else { error("mode", ERROR_INVALID_PARAMETER); return 2; }
    DebugSetProcessKillOnExit(FALSE);
    event("ready", 0, 0); printf(",\"schema\":1,\"architecture\":\"%s\"", sizeof(void *) == 8 ? "x86_64" : "x86"); end_event();
    for (;;)
    {
        while (next_command(line)) if (command(line, NULL, NULL) == 2) return 0;
        if (InterlockedCompareExchange(&input_closed, 0, 0)) { detach_all(); return 0; }
        if (!WaitForDebugEvent(&debug, 100)) continue;
        status = DBG_CONTINUE;
        if (debug.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            invalidate_frames();
            CREATE_PROCESS_DEBUG_INFO *info = &debug.u.CreateProcessInfo;
            char path[32768] = "";
            DWORD parent = 0, unix_pid = 0;
            HANDLE listing;
            PROCESSENTRY32 entry;
            typedef LONG (WINAPI *query_process_fn)(HANDLE, ULONG, void *, ULONG, ULONG *);
            query_process_fn query = (query_process_fn)(uintptr_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
            if (info->hFile) GetFinalPathNameByHandleA(info->hFile, path, sizeof(path), FILE_NAME_NORMALIZED);
            if (debug.dwProcessId != primary_pid && wine_console_host(info, path))
            {
                if (!ContinueDebugEvent(debug.dwProcessId, debug.dwThreadId, DBG_CONTINUE) ||
                    !DebugActiveProcessStop(debug.dwProcessId)) { error("exclude_console_host", GetLastError()); detach_all(); return 1; }
                event("process_excluded", debug.dwProcessId, debug.dwThreadId);
                printf(",\"reason\":\"Wine console host outside application tracing scope\",\"path\":"); string(path); end_event();
                if (info->hFile) CloseHandle(info->hFile);
                CloseHandle(info->hThread); CloseHandle(info->hProcess);
                continue;
            }
            for (i = 0; i < MAX_PROCESSES; i++) if (!processes[i].id) break;
            if (i == MAX_PROCESSES) { error("process_capacity", ERROR_NOT_ENOUGH_MEMORY); ContinueDebugEvent(debug.dwProcessId, debug.dwThreadId, DBG_CONTINUE); DebugActiveProcessStop(debug.dwProcessId); continue; }
            processes[i] = (struct process){.id = debug.dwProcessId, .handle = info->hProcess, .initial_break = TRUE}; active++;
#ifdef _WIN64
            {
                BOOL wow64 = FALSE;
                if (IsWow64Process(info->hProcess, &wow64) && wow64)
                {
                    error("architecture_mismatch_use_x86_collector", ERROR_NOT_SUPPORTED);
                    ContinueDebugEvent(debug.dwProcessId, debug.dwThreadId, DBG_CONTINUE);
                    DebugActiveProcessStop(debug.dwProcessId);
                    return 1;
                }
            }
#endif
            add_thread(debug.dwProcessId, debug.dwThreadId, info->hThread);
            if (!SymInitialize(info->hProcess, NULL, FALSE)) error("symbols_init", GetLastError());
            SymLoadModuleEx(info->hProcess, info->hFile, *path ? path : NULL, NULL, (DWORD64)(uintptr_t)info->lpBaseOfImage, 0, NULL, 0);
            listing = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            memset(&entry, 0, sizeof(entry)); entry.dwSize = sizeof(entry);
            if (listing != INVALID_HANDLE_VALUE)
            {
                if (Process32First(listing, &entry)) do { if (entry.th32ProcessID == debug.dwProcessId) { parent = entry.th32ParentProcessID; break; } } while (Process32Next(listing, &entry));
                CloseHandle(listing);
            }
            if (query) query(info->hProcess, 1101, &unix_pid, sizeof(unix_pid), NULL);
            event("process_create", debug.dwProcessId, debug.dwThreadId); printf(",\"parent_pid\":%lu,\"unix_pid\":%lu,\"base\":\"0x%llx\",\"path\":", parent, unix_pid, (DWORD64)(uintptr_t)info->lpBaseOfImage); string(path); end_event();
            if (info->hFile) CloseHandle(info->hFile);
        }
        else if (debug.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) { add_thread(debug.dwProcessId, debug.dwThreadId, debug.u.CreateThread.hThread); event("thread_create", debug.dwProcessId, debug.dwThreadId); end_event(); }
        else if (debug.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
        {
            event("thread_exit", debug.dwProcessId, debug.dwThreadId); printf(",\"code\":%lu", debug.u.ExitThread.dwExitCode); end_event();
            for (i = 0; i < MAX_THREADS; i++) if (threads[i].id == debug.dwThreadId && threads[i].pid == debug.dwProcessId)
            {
                unsigned point;
                struct process *p = process(debug.dwProcessId);
                if (threads[i].rearm)
                {
                    for (point = 0; point < MAX_BREAKPOINTS; point++) if (breakpoints[point].pid == debug.dwProcessId && breakpoints[point].address == threads[i].rearm)
                        breakpoints[point].armed = write_byte(p, threads[i].rearm, 0xcc);
                    resume_siblings(debug.dwProcessId);
                }
                CloseHandle(threads[i].handle); memset(threads + i, 0, sizeof(threads[i]));
            }
        }
        else if (debug.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            invalidate_frames();
            struct process *p = process(debug.dwProcessId);
            if (p)
            {
                char path[32768] = "";
                if (debug.u.LoadDll.hFile) GetFinalPathNameByHandleA(debug.u.LoadDll.hFile, path, sizeof(path), FILE_NAME_NORMALIZED);
                SymLoadModuleEx(p->handle, debug.u.LoadDll.hFile, *path ? path : NULL, NULL, (DWORD64)(uintptr_t)debug.u.LoadDll.lpBaseOfDll, 0, NULL, 0);
                event("module_load", debug.dwProcessId, debug.dwThreadId);
                printf(",\"base\":\"0x%llx\",\"path\":", (DWORD64)(uintptr_t)debug.u.LoadDll.lpBaseOfDll); string(path); end_event();
                if (*p->stop_module)
                {
                    const char *name = strrchr(path, '\\');
                    if (name && !_stricmp(name + 1, p->stop_module) && stopped(&debug, &status, "module") == 2) return 0;
                }
            }
            if (debug.u.LoadDll.hFile) CloseHandle(debug.u.LoadDll.hFile);
        }
        else if (debug.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT)
        {
            invalidate_frames();
            struct process *p = process(debug.dwProcessId);
            if (p) SymUnloadModule64(p->handle, (DWORD64)(uintptr_t)debug.u.UnloadDll.lpBaseOfDll);
            event("module_unload", debug.dwProcessId, debug.dwThreadId); printf(",\"base\":\"0x%llx\"", (DWORD64)(uintptr_t)debug.u.UnloadDll.lpBaseOfDll); end_event();
        }
        else if (debug.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT)
        {
            struct process *p = process(debug.dwProcessId);
            OUTPUT_DEBUG_STRING_INFO *info = &debug.u.DebugString;
            char text[8192];
            SIZE_T read;
            if (p && !info->fUnicode && info->nDebugStringLength > 8 && info->nDebugStringLength < sizeof(text) && ReadProcessMemory(p->handle, info->lpDebugStringData, text, info->nDebugStringLength, &read))
            {
                text[read < sizeof(text) ? read : sizeof(text) - 1] = 0;
                if (!strncmp(text, "EAGLE/1 ", 8))
                {
                    const char *caller = strstr(text + 8, "\"caller\":\"");
                    event("provider", debug.dwProcessId, debug.dwThreadId);
                    printf(",\"payload\":"); string(text + 8);
                    if (caller)
                    {
                        char *end;
                        DWORD64 address = strtoull(caller + 10, &end, 16);
                        if (address && end > caller + 10 && *end == '"' && end - caller <= 28)
                        {
                            printf(",\"frame\":"); frame(p->handle, address);
                        }
                    }
                    end_event();
                    if (getenv("EAGLE_TRIGGER_HRESULT"))
                    {
                        char match[64];
                        snprintf(match, sizeof(match), "\"hresult\":\"%.10s\"", getenv("EAGLE_TRIGGER_HRESULT"));
                        if (strstr(text + 8, match))
                        {
                            const char *action = getenv("EAGLE_TRIGGER_ACTION");
                            event("trigger", debug.dwProcessId, debug.dwThreadId); printf(",\"condition\":"); string(match); end_event();
                            snapshot(debug.dwProcessId, 0);
                            if (action && !strcmp(action, "dump")) dump(debug.dwProcessId, debug.dwThreadId, NULL);
                            if (action && !strcmp(action, "stop") && stopped(&debug, &status, "provider") == 2) return 0;
                        }
                    }
                }
            }
        }
        else if (debug.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            EXCEPTION_DEBUG_INFO *info = &debug.u.Exception;
            struct process *p = process(debug.dwProcessId);
            DWORD code = info->ExceptionRecord.ExceptionCode;
            DWORD64 address = (DWORD64)(uintptr_t)info->ExceptionRecord.ExceptionAddress;
            BOOL stop = !info->dwFirstChance, internal = FALSE;
            const char *reason = "exception";
            if (code == EXCEPTION_BREAKPOINT)
            {
                status = DBG_CONTINUE;
                if (p && p->initial_break) { p->initial_break = FALSE; stop = interactive; internal = TRUE; reason = "entry"; }
                if (p && p->pause_requested) { stop = TRUE; internal = TRUE; p->pause_requested = FALSE; reason = "pause"; }
                for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == debug.dwProcessId && breakpoints[i].address == address)
                {
                    unsigned t;
                    stop = TRUE;
                    reason = "breakpoint";
                    if (breakpoints[i].armed)
                    {
                        suspend_siblings(debug.dwProcessId, debug.dwThreadId);
                        if (!write_byte(p, address, breakpoints[i].original)) { detach_all(); return 1; }
                        breakpoints[i].armed = FALSE;
                    }
                    for (t = 0; t < MAX_THREADS; t++) if (threads[t].id == debug.dwThreadId && threads[t].pid == debug.dwProcessId)
                    {
                        CONTEXT c; memset(&c, 0, sizeof(c)); c.ContextFlags = CONTEXT_FULL;
                        if (GetThreadContext(threads[t].handle, &c))
                        {
#ifdef _WIN64
                            c.Rip = address;
#else
                            c.Eip = (DWORD)address;
#endif
                            if (!threads[t].saved_tf) { threads[t].original_tf = !!(c.EFlags & 0x100); threads[t].saved_tf = TRUE; }
                            c.EFlags |= 0x100;
                            if (!SetThreadContext(threads[t].handle, &c)) { error("breakpoint_context", GetLastError()); detach_all(); return 1; }
                            threads[t].rearm = address;
                            breakpoints[i].hits++;
                            stop = condition_matches(breakpoints + i, &c);
                            if (stop && breakpoints[i].logpoint)
                            {
                                event("breakpoint_log", debug.dwProcessId, debug.dwThreadId);
                                printf(",\"hits\":%llu,\"frame\":", breakpoints[i].hits); frame(p->handle, address); end_event();
                                snapshot(debug.dwProcessId, debug.dwThreadId); stop = FALSE;
                            }
                        }
                        else { error("breakpoint_context", GetLastError()); detach_all(); return 1; }
                    }
                    internal = TRUE; break;
                }
                if (!internal) status = DBG_EXCEPTION_NOT_HANDLED;
            }
            else if (code == EXCEPTION_SINGLE_STEP)
            {
                unsigned t;
                BOOL watch_hit = FALSE;
                DWORD64 watch_mask = 0;
                for (i = 0; i < 4; i++) if (watchpoints[i].pid == debug.dwProcessId && watchpoints[i].address) watch_mask |= (DWORD64)1 << i;
                for (t = 0; t < MAX_THREADS; t++) if (threads[t].id == debug.dwThreadId && threads[t].pid == debug.dwProcessId)
                {
                    CONTEXT context; memset(&context, 0, sizeof(context)); context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
                    if (!GetThreadContext(threads[t].handle, &context)) { error("step_context", GetLastError()); detach_all(); return 1; }
                    if (context.Dr6 & watch_mask)
                    {
                        watch_hit = TRUE;
                        event("watchpoint_hit", debug.dwProcessId, debug.dwThreadId); printf(",\"slots\":%llu", (unsigned long long)(context.Dr6 & watch_mask)); end_event();
                        context.Dr6 &= ~watch_mask;
                    }
                    internal = threads[t].stepping || threads[t].rearm || watch_hit;
                    stop = threads[t].stepping || watch_hit;
                    reason = watch_hit ? "data breakpoint" : "step";
                    threads[t].stepping = FALSE;
                    if (threads[t].rearm)
                    {
                        unsigned queued;
                        threads[t].rearm = 0;
                        for (queued = 0; queued < MAX_THREADS; queued++) if (threads[queued].pid == debug.dwProcessId && threads[queued].rearm) break;
                        if (queued < MAX_THREADS)
                        {
                            if (SuspendThread(threads[t].handle) == (DWORD)-1) { error("suspend_thread", GetLastError()); detach_all(); return 1; }
                            threads[t].suspended = TRUE;
                            if (threads[queued].suspended)
                            {
                                if (ResumeThread(threads[queued].handle) == (DWORD)-1) { error("resume_thread", GetLastError()); detach_all(); return 1; }
                                threads[queued].suspended = FALSE;
                            }
                        }
                        else
                        {
                            for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == debug.dwProcessId && !breakpoints[i].armed)
                            {
                                if (!write_byte(p, breakpoints[i].address, 0xcc)) { detach_all(); return 1; }
                                breakpoints[i].armed = TRUE;
                            }
                            resume_siblings(debug.dwProcessId);
                        }
                    }
                    if (threads[t].saved_tf)
                    {
                        context.EFlags = (context.EFlags & ~0x100) | (threads[t].original_tf ? 0x100 : 0);
                        threads[t].saved_tf = FALSE;
                    }
                    if (!SetThreadContext(threads[t].handle, &context)) { error("step_context", GetLastError()); detach_all(); return 1; }
                }
                status = internal ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
            }
            else status = DBG_EXCEPTION_NOT_HANDLED;
            event("exception", debug.dwProcessId, debug.dwThreadId);
            printf(",\"code\":\"0x%08lx\",\"first_chance\":%s,\"internal\":%s,\"frame\":", code, info->dwFirstChance ? "true" : "false", internal ? "true" : "false");
            if (p) frame(p->handle, address); else printf("null");
            if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) && info->ExceptionRecord.NumberParameters >= 2)
            {
                ULONG_PTR operation = info->ExceptionRecord.ExceptionInformation[0];
                printf(",\"access\":\"%s\",\"fault_address\":\"0x%llx\"", operation == 0 ? "read" : operation == 1 ? "write" : operation == 8 ? "execute" : "unknown", (unsigned long long)info->ExceptionRecord.ExceptionInformation[1]);
            }
            end_event();
            if (!info->dwFirstChance) { snapshot(debug.dwProcessId, 0); dump(debug.dwProcessId, debug.dwThreadId, &info->ExceptionRecord); }
            if (stop && interactive)
            {
                if (stopped(&debug, &status, reason) == 2) return 0;
            }
        }
        else if (debug.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            invalidate_frames();
            struct process *p = process(debug.dwProcessId);
            event("process_exit", debug.dwProcessId, debug.dwThreadId); printf(",\"code\":%lu", debug.u.ExitProcess.dwExitCode); end_event();
            if (p) { SymCleanup(p->handle); CloseHandle(p->handle); memset(p, 0, sizeof(*p)); active--; }
            for (i = 0; i < MAX_THREADS; i++) if (threads[i].pid == debug.dwProcessId) { CloseHandle(threads[i].handle); memset(threads + i, 0, sizeof(threads[i])); }
            for (i = 0; i < MAX_BREAKPOINTS; i++) if (breakpoints[i].pid == debug.dwProcessId) memset(breakpoints + i, 0, sizeof(breakpoints[i]));
        }
        if (!ContinueDebugEvent(debug.dwProcessId, debug.dwThreadId, status)) error("continue", GetLastError());
        if (!active) break;
    }
    event("finished", 0, 0); end_event();
    return 0;
}
