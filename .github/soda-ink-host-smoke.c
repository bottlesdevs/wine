/*
 * Copyright 2026 Mirko Brombin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define CONST_VTABLE
#define COBJMACROS
#define _WIN32_WINNT 0x0602
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <objbase.h>
#include <initguid.h>
#include "inkpresenterdesktop.h"

static LONG failures, sequence, destroyed;
static DWORD caller, worker;
static HANDLE gate, entered, finished;

#define check(expr) do { if (!(expr)) { printf("FAIL line %u: %s\n", __LINE__, #expr); InterlockedIncrement(&failures); } } while (0)

struct work_item
{
    IInkHostWorkItem iface;
    LONG ref;
    unsigned int index;
};

static HRESULT WINAPI work_query(IInkHostWorkItem *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IInkHostWorkItem)) return E_NOINTERFACE;
    *out = iface;
    IInkHostWorkItem_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI work_addref(IInkHostWorkItem *iface)
{
    struct work_item *item = CONTAINING_RECORD(iface, struct work_item, iface);
    return InterlockedIncrement(&item->ref);
}

static ULONG WINAPI work_release(IInkHostWorkItem *iface)
{
    struct work_item *item = CONTAINING_RECORD(iface, struct work_item, iface);
    ULONG ref = InterlockedDecrement(&item->ref);
    if (!ref)
    {
        unsigned int index = item->index;
        InterlockedIncrement(&destroyed);
        HeapFree(GetProcessHeap(), 0, item);
        if (index == 63) SetEvent(finished);
    }
    return ref;
}

static HRESULT WINAPI work_invoke(IInkHostWorkItem *iface)
{
    struct work_item *item = CONTAINING_RECORD(iface, struct work_item, iface);
    APTTYPE type;
    APTTYPEQUALIFIER qualifier;
    DWORD thread = GetCurrentThreadId();

    check(CoGetApartmentType(&type, &qualifier) == S_OK);
    check(type == APTTYPE_MTA);
    check(thread != caller);
    if (!item->index)
    {
        worker = thread;
        SetEvent(entered);
        check(WaitForSingleObject(gate, 10000) == WAIT_OBJECT_0);
    }
    check(thread == worker);
    check((unsigned int)InterlockedIncrement(&sequence) == item->index + 1);
    return item->index == 7 ? E_FAIL : S_OK;
}

static const IInkHostWorkItemVtbl work_vtbl = {work_query, work_addref, work_release, work_invoke};

struct marshal_context
{
    IStream *stream;
    DWORD apartment;
};

static DWORD WINAPI marshal_thread(void *arg)
{
    struct marshal_context *context = arg;
    IInkDesktopHost *host = NULL;
    HRESULT hr;

    check(CoInitializeEx(NULL, context->apartment) == S_OK);
    hr = CoGetInterfaceAndReleaseStream(context->stream, &IID_IInkDesktopHost, (void **)&host);
    check(hr == S_OK);
    if (SUCCEEDED(hr))
    {
        check(IInkDesktopHost_QueueWorkItem(host, NULL) == E_POINTER);
        IInkDesktopHost_Release(host);
    }
    CoUninitialize();
    return 0;
}

int main(int argc, char **argv)
{
    HRESULT (WINAPI *can_unload)(void);
    IInkDesktopHost *host = NULL;
    IClassFactory *factory = NULL;
    IUnknown *identity = NULL;
    IMarshal *marshaler = NULL;
    struct work_item *item;
    struct marshal_context context;
    HANDLE thread;
    HMODULE module;
    HRESULT hr;
    unsigned int i;

    caller = GetCurrentThreadId();
    hr = CoInitializeEx(NULL, argc > 1 && argv[1][0] == 's' ? COINIT_APARTMENTTHREADED : COINIT_MULTITHREADED);
    check(hr == S_OK);
    hr = CoCreateInstance(&CLSID_InkDesktopHost, NULL, CLSCTX_INPROC_SERVER, &IID_IInkDesktopHost, (void **)&host);
    printf("CoCreateInstance=%#lx bits=%u apartment=%s\n", hr, (unsigned int)(8 * sizeof(void *)), argc > 1 ? argv[1] : "mta");
    if (FAILED(hr)) return 2;
    module = LoadLibraryW(L"inkobjcore.dll");
    check(module != NULL);
    can_unload = (void *)GetProcAddress(module, "DllCanUnloadNow");
    check(can_unload != NULL);
    check(can_unload() == S_FALSE);
    check(IInkDesktopHost_QueryInterface(host, &IID_IUnknown, (void **)&identity) == S_OK);
    check(identity == (IUnknown *)host);
    IUnknown_Release(identity);
    check(IInkDesktopHost_QueryInterface(host, &IID_IAgileObject, (void **)&identity) == S_OK);
    check(identity == (IUnknown *)host);
    IUnknown_Release(identity);
    check(IInkDesktopHost_QueryInterface(host, &IID_IMarshal, (void **)&marshaler) == S_OK);
    IMarshal_Release(marshaler);
    check(IInkDesktopHost_QueueWorkItem(host, NULL) == E_POINTER);
    context.apartment = argc > 1 && argv[1][0] == 's' ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED;
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkDesktopHost, (IUnknown *)host, &context.stream) == S_OK);
    thread = CreateThread(NULL, 0, marshal_thread, &context, 0, NULL);
    check(thread != NULL);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    finished = CreateEventW(NULL, TRUE, FALSE, NULL);
    check(gate && entered && finished);
    for (i = 0; i < 64; ++i)
    {
        item = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*item));
        item->iface.lpVtbl = &work_vtbl;
        item->ref = 1;
        item->index = i;
        check(IInkDesktopHost_QueueWorkItem(host, &item->iface) == S_OK);
        IInkHostWorkItem_Release(&item->iface);
        if (!i) check(WaitForSingleObject(entered, 10000) == WAIT_OBJECT_0);
    }
    IInkDesktopHost_Release(host);
    check(can_unload() == S_FALSE);
    SetEvent(gate);
    check(WaitForSingleObject(finished, 10000) == WAIT_OBJECT_0);
    check(sequence == 64);
    check(destroyed == 64);
    for (i = 0; i < 1000 && can_unload() != S_OK; ++i) Sleep(10);
    check(can_unload() == S_OK);
    check(CoGetClassObject(&CLSID_InkDesktopHost, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&factory) == S_OK);
    check(can_unload() == S_FALSE);
    check(IClassFactory_LockServer(factory, TRUE) == S_OK);
    IClassFactory_Release(factory);
    check(can_unload() == S_FALSE);
    check(CoGetClassObject(&CLSID_InkDesktopHost, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&factory) == S_OK);
    check(IClassFactory_LockServer(factory, FALSE) == S_OK);
    IClassFactory_Release(factory);
    check(can_unload() == S_OK);
    CloseHandle(gate);
    CloseHandle(entered);
    CloseHandle(finished);
    FreeLibrary(module);
    CoUninitialize();
    printf("QUEUE_RESULT callbacks=%ld destroyed=%ld failures=%ld\n", sequence, destroyed, failures);
    return failures ? 1 : 0;
}
