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
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <winstring.h>
#include <initguid.h>
#include <roapi.h>
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#define WIDL_using_Windows_Foundation_Numerics
#define WIDL_using_Windows_UI
#define WIDL_using_Windows_UI_Core
#define WIDL_using_Windows_UI_Composition
#define WIDL_using_Windows_UI_Input_Inking
#define WIDL_using_Windows_UI_Input_Inking_Core
#include "windows.ui.input.inking.core.h"

static LONG checks, failures;
#define check(expr) do { InterlockedIncrement(&checks); if (!(expr)) { printf("FAIL line %u: %s\n", __LINE__, #expr); InterlockedIncrement(&failures); } } while (0)

struct marshal_context
{
    IStream *sync, *view, *iterator;
    DWORD apartment;
};

static DWORD WINAPI consume_batch(void *arg)
{
    struct marshal_context *context = arg;
    IInkSynchronizer *sync;
    IVectorView_InkStroke *view, *invalid;
    IIterator_InkStroke *iterator;
    IInkStroke *item;
    UINT32 size;
    boolean current;
    check(CoInitializeEx(NULL, context->apartment) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->sync, &IID_IInkSynchronizer, (void **)&sync) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->view, &IID_IVectorView_InkStroke, (void **)&view) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->iterator, &IID_IIterator_InkStroke, (void **)&iterator) == S_OK);
    check(IVectorView_InkStroke_get_Size(view, &size) == S_OK && !size);
    check(IIterator_InkStroke_get_HasCurrent(iterator, &current) == S_OK && !current);
    item = (void *)1;
    check(IIterator_InkStroke_get_Current(iterator, &item) == E_BOUNDS && !item);
    invalid = (void *)1;
    check(IInkSynchronizer_BeginDry(sync, &invalid) == E_ILLEGAL_METHOD_CALL && !invalid);
    check(IInkSynchronizer_EndDry(sync) == S_OK);
    IInkSynchronizer_Release(sync);
    check(IVectorView_InkStroke_get_Size(view, &size) == S_OK && !size);
    IVectorView_InkStroke_Release(view);
    IIterator_InkStroke_Release(iterator);
    CoUninitialize();
    return 0;
}

int main(int argc, char **argv)
{
    HRESULT (WINAPI *can_unload)(void);
    ICoreInkPresenterHost *host;
    IInspectable *instance;
    IInkPresenter *presenter;
    IInkSynchronizer *sync, *same;
    IVectorView_InkStroke *view, *invalid;
    IIterable_InkStroke *iterable;
    IIterator_InkStroke *iterator;
    IInkStroke *item;
    UINT32 size;
    HSTRING name;
    HMODULE module;
    HANDLE thread;
    HRESULT hr;
    struct marshal_context context;
    BOOL sta = argc > 1 && argv[1][0] == 's';

    check(RoInitialize(sta ? RO_INIT_SINGLETHREADED : RO_INIT_MULTITHREADED) == S_OK);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost), &name) == S_OK);
    check(RoActivateInstance(name, &instance) == S_OK);
    WindowsDeleteString(name);
    check(IInspectable_QueryInterface(instance, &IID_ICoreInkPresenterHost, (void **)&host) == S_OK);
    IInspectable_Release(instance);
    check(ICoreInkPresenterHost_get_InkPresenter(host, &presenter) == S_OK);
    hr = IInkPresenter_ActivateCustomDrying(presenter, &sync);
    printf("CUSTOM_DRYING=%#lx bits=%u apartment=%s\n", hr, (unsigned int)(8 * sizeof(void *)), sta ? "sta" : "mta");
    if (FAILED(hr))
    {
        IInkPresenter_Release(presenter);
        ICoreInkPresenterHost_Release(host);
        RoUninitialize();
        return 2;
    }
    module = LoadLibraryW(L"inkobjcore.dll");
    check(module != NULL);
    can_unload = (void *)GetProcAddress(module, "DllCanUnloadNow");
    check(can_unload != NULL && can_unload() == S_FALSE);
    check(IInkPresenter_ActivateCustomDrying(presenter, &same) == S_OK && same == sync);
    IInkSynchronizer_Release(same);
    check(IInkSynchronizer_BeginDry(sync, NULL) == E_POINTER);
    check(IInkSynchronizer_BeginDry(sync, &view) == S_OK);
    check(IVectorView_InkStroke_get_Size(view, &size) == S_OK && !size);
    item = (void *)1;
    check(IVectorView_InkStroke_GetAt(view, 0, &item) == E_BOUNDS && !item);
    invalid = (void *)1;
    check(IInkSynchronizer_BeginDry(sync, &invalid) == E_ILLEGAL_METHOD_CALL && !invalid);
    check(IVectorView_InkStroke_QueryInterface(view, &IID_IIterable_InkStroke, (void **)&iterable) == S_OK);
    check(IIterable_InkStroke_First(iterable, &iterator) == S_OK);
    IIterable_InkStroke_Release(iterable);
    context.apartment = sta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED;
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkSynchronizer, (IUnknown *)sync, &context.sync) == S_OK);
    check(CoMarshalInterThreadInterfaceInStream(&IID_IVectorView_InkStroke, (IUnknown *)view, &context.view) == S_OK);
    check(CoMarshalInterThreadInterfaceInStream(&IID_IIterator_InkStroke, (IUnknown *)iterator, &context.iterator) == S_OK);
    ICoreInkPresenterHost_Release(host);
    IInkPresenter_Release(presenter);
    IInkSynchronizer_Release(sync);
    IVectorView_InkStroke_Release(view);
    IIterator_InkStroke_Release(iterator);
    thread = CreateThread(NULL, 0, consume_batch, &context, 0, NULL);
    check(thread != NULL);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    RoUninitialize();
    check(can_unload() == S_OK);
    FreeLibrary(module);
    printf("INK_DRYING_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}