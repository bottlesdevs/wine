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

#define COBJMACROS
#define INITGUID
#include <stdio.h>
#include "windows.h"
#include "winstring.h"
#include "roapi.h"
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Foundation_Numerics
#include "windows.foundation.numerics.h"
#define WIDL_using_Windows_UI
#include "windows.ui.h"
#define WIDL_using_Windows_UI_Composition
#include "windows.ui.composition.h"
#define WIDL_using_Windows_UI_Composition_Core
#include "windows.ui.composition.core.h"
#define WIDL_using_Windows_UI_Composition_Desktop
#include "windows.ui.composition.interop.h"
#define WIDL_using_Windows_UI_Composition_Interactions
#include "windows.ui.composition.interactions.h"

static void check(const char *name,HRESULT hr)
{
    if(FAILED(hr)){printf("FAIL %s %08lx\n",name,(unsigned long)hr);fflush(stdout);ExitProcess(2);}
}
static HSTRING string(const WCHAR *text)
{
    HSTRING value;check("string",WindowsCreateString(text,lstrlenW(text),&value));return value;
}
static ICompositionAnimation *animation(ICompositor *compositor,const WCHAR *text,const WCHAR *key,ICompositionObject *reference)
{
    IExpressionAnimation *expression;
    ICompositionAnimation *value;
    HSTRING source=string(text),name;
    check("expression",ICompositor_CreateExpressionAnimationWithExpression(compositor,source,&expression));
    WindowsDeleteString(source);
    check("animation",IExpressionAnimation_QueryInterface(expression,&IID_ICompositionAnimation,(void **)&value));
    if(reference){name=string(key);check("reference",ICompositionAnimation_SetReferenceParameter(value,name,reference));WindowsDeleteString(name);}
    IExpressionAnimation_Release(expression);return value;
}
static void start(ICompositor *compositor,ICompositionObject *target,const WCHAR *property,const WCHAR *text,const WCHAR *key,ICompositionObject *reference)
{
    ICompositionAnimation *value=animation(compositor,text,key,reference);
    HSTRING name=string(property);
    check("start",ICompositionObject_StartAnimation(target,name,value));
    WindowsDeleteString(name);ICompositionAnimation_Release(value);
}
static BOOL verify_pixels;
static void stage(ICompositorController *controller,const char *name)
{
    MSG message;UINT i;
    for(i=0;i<2;++i){check("commit",ICompositorController_Commit(controller));while(PeekMessageW(&message,NULL,0,0,PM_REMOVE))DispatchMessageW(&message);Sleep(200);}
    if (verify_pixels)
    {
        int left = !strcmp(name,"INITIAL") ? 50 : !strcmp(name,"RESIZED") ? 70 : 40;
        HDC screen = GetDC(NULL);
        COLORREF inside = GetPixel(screen,left+5,35), before = GetPixel(screen,left-1,35), after = GetPixel(screen,left+20,35);
        ReleaseDC(NULL,screen);
        printf("TRACKER_GDI_PIXELS_%s=%08lx,%08lx,%08lx\n",name,(unsigned long)inside,(unsigned long)before,(unsigned long)after);
        if (inside != RGB(255,0,0) || before != RGB(255,255,255) || after != RGB(255,255,255)) ExitProcess(7);
    }
    printf("TRACKER_%s_CAPTURE_READY\n",name);fflush(stdout);Sleep(1200);
}
struct stress_context{ICompositionObject *object;IInteractionTracker *tracker;ICompositionAnimation *animation;};
static DWORD WINAPI writer(void *data)
{
    struct stress_context *context=data;
    HSTRING name=string(L"MinPosition.Y");UINT i;
    for(i=0;i<500;++i){check("stress start",ICompositionObject_StartAnimation(context->object,name,context->animation));check("stress stop",ICompositionObject_StopAnimation(context->object,name));}
    WindowsDeleteString(name);return 0;
}
static DWORD WINAPI reader(void *data)
{
    struct stress_context *context=data;struct Vector3 value;UINT i;
    for(i=0;i<1000;++i)check("stress read",IInteractionTracker_get_Position(context->tracker,&value));
    return 0;
}
int main(int argc,char **argv)
{
    IInspectable *instance;ICompositorController *controller;ICompositor *compositor;
    ICompositorDesktopInterop *desktop;IDesktopWindowTarget *desktop_target;ICompositionTarget *target;
    ICompositionColorBrush *color;ICompositionBrush *brush;ISpriteVisual *sprite;IVisual *visual;
    ICompositionObject *object,*tracker_object,*layout_object;
    IInteractionTrackerStatics *factory;IInteractionTracker *tracker;ICompositionPropertySet *layout;
    IClosable *closable;HSTRING name,size;HWND window;INT32 request;struct Vector3 position;
    HRESULT result;ULONG refs_before,refs_after;HANDLE threads[2];struct stress_context stress;
    BOOL candidate=argc>1;
    verify_pixels=candidate;

    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
    check("tracker factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
    check("tracker",IInteractionTrackerStatics_Create(factory,compositor,&tracker));IInteractionTrackerStatics_Release(factory);
    check("tracker object",IInteractionTracker_QueryInterface(tracker,&IID_ICompositionObject,(void **)&tracker_object));
    check("max scale",IInteractionTracker_put_MaxScale(tracker,4));
    check("scale",IInteractionTracker_TryUpdateScale(tracker,2,((struct Vector3){0}),&request));
    check("layout",ICompositor_CreatePropertySet(compositor,&layout));
    check("layout object",ICompositionPropertySet_QueryInterface(layout,&IID_ICompositionObject,(void **)&layout_object));
    size=string(L"ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");check("layout size",ICompositionPropertySet_InsertVector3(layout,size,((struct Vector3){80,20,0})));
    start(compositor,tracker_object,L"MinPosition.X",L"-layout.ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.X / this.target.Scale",L"layout",layout_object);
    start(compositor,tracker_object,L"MaxPosition.X",L"-layout.ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.X / this.target.Scale",L"layout",layout_object);
    ICompositionPropertySet_AddRef(layout);refs_before=ICompositionPropertySet_Release(layout);
    printf("LAYOUT_REFS_ACTIVE=%lu\n",refs_before);
    check("desktop",ICompositor_QueryInterface(compositor,&IID_ICompositorDesktopInterop,(void **)&desktop));
    window=CreateWindowExW(0,L"STATIC",L"Dynamic tracker pixel test",WS_POPUP,10,10,160,100,NULL,NULL,GetModuleHandleW(NULL),NULL);if(!window)return 3;
    ShowWindow(window,SW_SHOWNOACTIVATE);
    check("target",ICompositorDesktopInterop_CreateDesktopWindowTarget(desktop,window,FALSE,&desktop_target));
    check("target interface",IDesktopWindowTarget_QueryInterface(desktop_target,&IID_ICompositionTarget,(void **)&target));
    check("color",ICompositor_CreateColorBrushWithColor(compositor,((struct Color){255,255,0,0}),&color));
    check("brush",ICompositionColorBrush_QueryInterface(color,&IID_ICompositionBrush,(void **)&brush));
    check("sprite",ICompositor_CreateSpriteVisual(compositor,&sprite));
    check("visual",ISpriteVisual_QueryInterface(sprite,&IID_IVisual,(void **)&visual));
    check("object",IVisual_QueryInterface(visual,&IID_ICompositionObject,(void **)&object));
    check("size",IVisual_put_Size(visual,((struct Vector2){20,15})));
    check("offset",IVisual_put_Offset(visual,((struct Vector3){0,20,0})));
    check("brush set",ISpriteVisual_put_Brush(sprite,brush));
    start(compositor,object,L"Offset.X",L"-tracker.Position.X",L"tracker",tracker_object);
    check("root",ICompositionTarget_put_Root(target,visual));
    stage(controller,"INITIAL");
    check("position",IInteractionTracker_get_Position(tracker,&position));printf("INITIAL_POSITION=%g\n",position.X);
    check("resize",ICompositionPropertySet_InsertVector3(layout,size,((struct Vector3){120,20,0})));
    stage(controller,"RESIZED");
    check("zoom",IInteractionTracker_TryUpdateScale(tracker,4,((struct Vector3){0}),&request));
    stage(controller,"SCALED");
    if(candidate)
    {
        stress.object=tracker_object;stress.tracker=tracker;stress.animation=animation(compositor,L"0",NULL,NULL);
        threads[0]=CreateThread(NULL,0,writer,&stress,0,NULL);threads[1]=CreateThread(NULL,0,reader,&stress,0,NULL);
        if(!threads[0]||!threads[1]||WaitForMultipleObjects(2,threads,TRUE,15000)!=WAIT_OBJECT_0)return 4;
        CloseHandle(threads[0]);CloseHandle(threads[1]);ICompositionAnimation_Release(stress.animation);
        puts("TRACKER_CONCURRENT_500_WRITES_1000_READS_PASS");
    }
    {
        const WCHAR *expressions[] = {L"this.target.Position.X", L"this.target.position.x", L"This.Target.POSITION.X"};
        UINT i;

        for (i = 0; i < sizeof(expressions) / sizeof(expressions[0]); ++i)
        {
            start(compositor,tracker_object,L"MinPosition.X",expressions[i],NULL,NULL);
            result=IInteractionTracker_get_Position(tracker,&position);
            printf("SELF_POSITION_%u_RESULT=%08lx\n",i,(unsigned long)result);
            if(candidate && (FAILED(result) || position.X!=-30))return 5;
        }
    }
    stage(controller,"POSITION");
    start(compositor,tracker_object,L"MinPosition.X",L"1/0",NULL,NULL);
    stage(controller,"INVALID");
    check("closable",IInteractionTracker_QueryInterface(tracker,&IID_IClosable,(void **)&closable));
    check("close",IClosable_Close(closable));check("close again",IClosable_Close(closable));IClosable_Release(closable);
    ICompositionPropertySet_AddRef(layout);refs_after=ICompositionPropertySet_Release(layout);
    printf("LAYOUT_REFS_CLOSED=%lu\n",refs_after);if(candidate && (refs_before!=4||refs_after!=2))return 6;
    check("detach",ICompositionTarget_put_Root(target,NULL));
    ICompositionObject_Release(object);IVisual_Release(visual);ISpriteVisual_Release(sprite);
    ICompositionBrush_Release(brush);ICompositionColorBrush_Release(color);
    ICompositionObject_Release(tracker_object);IInteractionTracker_Release(tracker);
    ICompositionObject_Release(layout_object);ICompositionPropertySet_Release(layout);WindowsDeleteString(size);
    ICompositionTarget_Release(target);IDesktopWindowTarget_Release(desktop_target);ICompositorDesktopInterop_Release(desktop);
    ICompositor_Release(compositor);ICompositorController_Release(controller);DestroyWindow(window);RoUninitialize();puts("TRACKER_DONE");return 0;
}
