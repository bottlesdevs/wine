#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

struct thread_case { unsigned index; DWORD failed; };

static void reset(void)
{
    SetLastError(0x12345678);
    NtCurrentTeb()->LastStatusValue=0xc0000022;
}

static BOOL preserved(void)
{
    return GetLastError()==0x12345678 && NtCurrentTeb()->LastStatusValue==0xc0000022;
}

static DWORD WINAPI worker(void *arg)
{
    struct thread_case *item=arg;
    WCHAR text[64];
    UNICODE_STRING name;
    HMODULE module=NULL;
    NTSTATUS status;
    swprintf(text,ARRAY_SIZE(text),L"EagleThreadMissing%02u.dll",item->index);
    RtlInitUnicodeString(&name,text);
    reset();
    status=LdrLoadDll(NULL,0,&name,&module);
    item->failed=status!=(NTSTATUS)0xc0000135 || !preserved();
    return item->failed;
}

static void record(FILE *output, const char *operation, NTSTATUS result)
{
    DWORD error=GetLastError();
    ULONG status=NtCurrentTeb()->LastStatusValue;
    fprintf(output,"%s result=%08lx error=%08lx status=%08lx\n",operation,result,error,status);
}

static int missing_dependency(FILE *output,const char *library_path)
{
    WCHAR path[1024];
    UNICODE_STRING name;
    ANSI_STRING export_name;
    HMODULE module=NULL;
    PVOID address=NULL;
    NTSTATUS status;
    if(!MultiByteToWideChar(CP_UTF8,0,library_path,-1,path,ARRAY_SIZE(path))) return 2;
    reset();
    module=LoadLibraryExW(path,NULL,0);
    if(module || GetLastError()!=ERROR_MOD_NOT_FOUND) return 3;
    record(output,"win32_parent_missing_child",0);
    RtlInitUnicodeString(&name,path);
    reset();
    status=LdrLoadDll(NULL,0,&name,&module);
    record(output,"native_parent_missing_child",status);
    if(status!=(NTSTATUS)0xc0000135) return 4;
    RtlInitUnicodeString(&name,L"EagleNativeMissingFixture.dll");
    reset();
    status=LdrLoadDll(NULL,0,&name,&module);
    record(output,"native_direct_missing",status);
    if(status!=(NTSTATUS)0xc0000135) return 5;
    RtlInitAnsiString(&export_name,"EagleNativeMissingExport");
    reset();
    status=LdrGetProcedureAddress(GetModuleHandleW(L"kernel32.dll"),&export_name,0,&address);
    record(output,"native_export_missing",status);
    if(status!=(NTSTATUS)0xc000007a) return 6;
    reset();
    status=LdrGetProcedureAddress(GetModuleHandleW(L"kernel32.dll"),NULL,65535,&address);
    record(output,"native_ordinal_missing",status);
    if(status!=(NTSTATUS)0xc000007a) return 17;
    RtlInitUnicodeString(&name,L"EagleInvalidSearchFlags.dll");
    reset();
    status=LdrLoadDll((const WCHAR *)(ULONG_PTR)(LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_LIBRARY_SEARCH_SYSTEM32 | 1),NULL,&name,&module);
    record(output,"native_search_flags_invalid",status);
    if(status!=(NTSTATUS)0xc000000d) return 14;
    reset();
    status=LdrUnloadDll(NULL);
    record(output,"native_unload_missing",status);
    if(status!=(NTSTATUS)0xc0000135) return 15;
    return 0;
}

int main(int argc,char **argv)
{
    FILE *output;
    UNICODE_STRING library;
    ANSI_STRING name;
    HMODULE module=NULL;
    PVOID address=NULL;
    NTSTATUS status;
    unsigned i;
    if(argc!=4 || !(output=fopen(argv[2],"w"))) return 1;
    if(!strcmp(argv[3],"missing"))
    {
        int result=missing_dependency(output,argv[1]);
        if(result) return result;
    }
    else if(!strcmp(argv[3],"threads"))
    {
        struct thread_case cases[16];
        HANDLE threads[16];
        for(i=0;i<16;++i)
        {
            cases[i].index=i;cases[i].failed=1;
            threads[i]=CreateThread(NULL,0,worker,&cases[i],0,NULL);
            if(!threads[i]) return 2;
        }
        if(WaitForMultipleObjects(16,threads,TRUE,30000)!=WAIT_OBJECT_0) return 3;
        for(i=0;i<16;++i)
        {
            CloseHandle(threads[i]);
            fprintf(output,"thread%02u=%lu\n",i,cases[i].failed);
            if(cases[i].failed) return 4;
        }
    }
    else
    {
        char text[601];
        RtlInitUnicodeString(&library,L"kernel32.dll");
        reset();
        status=LdrLoadDll(NULL,0,&library,&module);
        if(status || !preserved()) return 5;
        RtlInitAnsiString(&name,"GetCurrentThreadId");
        reset();
        status=LdrGetProcedureAddress(module,&name,0,&address);
        if(status || !address || !preserved()) return 6;
        reset();
        status=LdrUnloadDll(module);
        if(status || !preserved()) return 16;
        fprintf(output,"native_success_and_state=PASS\n");
        if(!strcmp(argv[3],"budget"))
        {
            RtlInitAnsiString(&name,"EagleBudgetMissing");
            for(i=0;i<4100;++i)
            {
                reset();status=LdrGetProcedureAddress(module,&name,0,&address);
                if(status!=(NTSTATUS)0xc000007a || !preserved()) return 7;
            }
            fprintf(output,"budget_api_states=4100\n");
        }
        else if(!strcmp(argv[3],"names"))
        {
            const char *special="EagleMissing\"Quote";
            RtlInitAnsiString(&name,special);
            reset();status=LdrGetProcedureAddress(module,&name,0,&address);
            if(status!=(NTSTATUS)0xc000007a || !preserved()) return 8;
            memset(text,'X',200);text[200]=0;RtlInitAnsiString(&name,text);
            reset();status=LdrGetProcedureAddress(module,&name,0,&address);
            if(status!=(NTSTATUS)0xc000007a || !preserved()) return 9;
            memset(text,'Y',600);text[600]=0;RtlInitAnsiString(&name,text);
            reset();status=LdrGetProcedureAddress(module,&name,0,&address);
            if(status!=(NTSTATUS)0xc000007a || !preserved()) return 10;
            RtlInitUnicodeString(&library,L"C:\\private-path-sentinel\\EagleBoundsMissing.dll");
            reset();status=LdrLoadDll(NULL,0,&library,&module);
            if(status!=(NTSTATUS)0xc0000135 || !preserved()) return 11;
            fprintf(output,"native_names_and_state=PASS\n");
        }
        else return 12;
    }
    if(fclose(output)) return 13;
    puts("NATIVE_LOADER_STRESS_OK");
    return 0;
}
