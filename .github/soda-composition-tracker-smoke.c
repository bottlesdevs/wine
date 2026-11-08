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
#include "dispatcherqueue.h"

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
static BOOL verify_pixels, inspect_pixels, pump_events;
static HWND pixel_window;
static ICompositionColorBrush *pixel_color;
static void stage(ICompositorController *controller,IVisual *visual,const char *name)
{
    MSG message;UINT i;
    for(i=0;i<2;++i)
    {
        ULONGLONG end=GetTickCount64()+200;
        check("commit",ICompositorController_Commit(controller));
        do
        {
            while(PeekMessageW(&message,NULL,0,0,PM_REMOVE))DispatchMessageW(&message);
            if(!pump_events)break;
            MsgWaitForMultipleObjects(0,NULL,FALSE,10,QS_ALLINPUT);
        }while(GetTickCount64()<end);
        if(!pump_events)Sleep(200);
    }
    if (verify_pixels)
    {
        int left = !strcmp(name,"INITIAL") ? 50 : !strcmp(name,"RESIZED") ? 70 : 40;
        HDC screen = GetDC(NULL);
        COLORREF inside = GetPixel(screen,left+5,35), before = GetPixel(screen,left-1,35), after = GetPixel(screen,left+20,35);
        ReleaseDC(NULL,screen);
        printf("TRACKER_GDI_PIXELS_%s=%08lx,%08lx,%08lx\n",name,(unsigned long)inside,(unsigned long)before,(unsigned long)after);
        if (inspect_pixels)
        {
            RECT rect;
            HWND hit,child;
            WCHAR class_name[80];
            struct Vector3 offset,scale;
            struct Vector2 size;
            struct Color color;
            boolean visible;
            FLOAT opacity;
            POINT point = {left - 10 + 5, 25};
            GetWindowRect(pixel_window, &rect);
            ClientToScreen(pixel_window, &point);
            screen = GetDC(NULL);
            inside = GetPixel(screen, point.x, point.y);
            ReleaseDC(NULL, screen);
            printf("TRACKER_WINDOW_%s=%ld,%ld,%ld,%ld client_pixel=%08lx\n", name,
                    rect.left, rect.top, rect.right, rect.bottom, (unsigned long)inside);
            hit=WindowFromPoint(point);
            class_name[0]=0;
            GetClassNameW(hit,class_name,ARRAYSIZE(class_name));
            printf("TRACKER_HIT_%s parent=%p hit=%p class=%ls\n",name,(void *)pixel_window,(void *)hit,class_name);
            if((child=GetTopWindow(pixel_window)))
            {
                GetWindowRect(child,&rect);
                printf("TRACKER_LAYER_%s visible=%d rect=%ld,%ld,%ld,%ld style=%08lx exstyle=%08lx\n",name,
                        IsWindowVisible(child),rect.left,rect.top,rect.right,rect.bottom,
                        (unsigned long)GetWindowLongW(child,GWL_STYLE),(unsigned long)GetWindowLongW(child,GWL_EXSTYLE));
            }
            else printf("TRACKER_LAYER_%s absent\n",name);
            check("inspect visual offset",IVisual_get_Offset(visual,&offset));
            check("inspect visual size",IVisual_get_Size(visual,&size));
            printf("TRACKER_VISUAL_%s offset=%g,%g,%g size=%g,%g\n",name,
                    offset.X,offset.Y,offset.Z,size.X,size.Y);
            check("inspect visual visibility",IVisual_get_IsVisible(visual,&visible));
            check("inspect visual opacity",IVisual_get_Opacity(visual,&opacity));
            check("inspect visual scale",IVisual_get_Scale(visual,&scale));
            check("inspect brush color",ICompositionColorBrush_get_Color(pixel_color,&color));
            printf("TRACKER_PAINT_%s visible=%u opacity=%g scale=%g,%g,%g color=%u,%u,%u,%u\n",name,
                    (unsigned)visible,opacity,scale.X,scale.Y,scale.Z,
                    (unsigned)color.A,(unsigned)color.R,(unsigned)color.G,(unsigned)color.B);
        }
        else if (inside != RGB(255,0,0) || before != RGB(255,255,255) || after != RGB(255,255,255)) ExitProcess(7);
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
    ICompositionObject *object,*tracker_object=NULL,*layout_object=NULL;
    IInteractionTrackerStatics *factory;IInteractionTracker *tracker=NULL;ICompositionPropertySet *layout=NULL;
    IClosable *closable;HSTRING name,size=NULL;HWND window;INT32 request;struct Vector3 position;
    HRESULT result;ULONG refs_before=0,refs_after;HANDLE threads[2];struct stress_context stress;
    PDISPATCHERQUEUECONTROLLER queue=NULL;
    DispatcherQueueOptions options={sizeof(options),DQTYPE_THREAD_CURRENT,DQTAT_COM_NONE};
    BOOL flat=argc>2 && strstr(argv[2], "flat");
    BOOL simple=argc>2 && strstr(argv[2], "simple");
    BOOL short_key=argc>2 && strstr(argv[2], "short");
    BOOL green=argc>2 && strstr(argv[2], "green");
    BOOL pow2=argc>2 && strstr(argv[2], "pow2");
    BOOL topmost=argc>2 && strstr(argv[2], "top");
    BOOL custom=argc>2 && strstr(argv[2], "custom");
    BOOL update=argc>2 && strstr(argv[2], "update");
    WNDCLASSW cls={0};
    BOOL candidate=argc>1 && strcmp(argv[1], "inspect");
    inspect_pixels=argc>1 && !strcmp(argv[1], "inspect");
    verify_pixels=candidate || inspect_pixels;
    pump_events=argc>2 && strstr(argv[2], "pump");

    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    if(argc>2 && strstr(argv[2], "queue"))
    {
        HRESULT (WINAPI *create_queue)(DispatcherQueueOptions,PDISPATCHERQUEUECONTROLLER *);
        HMODULE module=LoadLibraryExW(L"CoreMessaging.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!module)return 8;
        create_queue=(void *)GetProcAddress(module,"CreateDispatcherQueueController");
        if(!create_queue)return 8;
        check("dispatcher queue",create_queue(options,&queue));
        puts("TRACKER_QUEUE_READY");
    }
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    if(!simple)
    {
        name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
        check("tracker factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
        check("tracker",IInteractionTrackerStatics_Create(factory,compositor,&tracker));IInteractionTrackerStatics_Release(factory);
        check("tracker object",IInteractionTracker_QueryInterface(tracker,&IID_ICompositionObject,(void **)&tracker_object));
        check("max scale",IInteractionTracker_put_MaxScale(tracker,4));
        check("scale",IInteractionTracker_TryUpdateScale(tracker,2,((struct Vector3){0}),&request));
        check("layout",ICompositor_CreatePropertySet(compositor,&layout));
        check("layout object",ICompositionPropertySet_QueryInterface(layout,&IID_ICompositionObject,(void **)&layout_object));
        size=string(short_key ? L"Viewport" : L"ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");check("layout size",ICompositionPropertySet_InsertVector3(layout,size,((struct Vector3){80,20,0})));
        start(compositor,tracker_object,L"MinPosition.X",short_key ? L"-layout.Viewport.X / this.target.Scale" : L"-layout.ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.X / this.target.Scale",L"layout",layout_object);
        start(compositor,tracker_object,L"MaxPosition.X",short_key ? L"-layout.Viewport.X / this.target.Scale" : L"-layout.ViewportDimensionsForScalarExpressionRegression_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.X / this.target.Scale",L"layout",layout_object);
        ICompositionPropertySet_AddRef(layout);refs_before=ICompositionPropertySet_Release(layout);
        printf("LAYOUT_REFS_ACTIVE=%lu\n",refs_before);
    }
    check("desktop",ICompositor_QueryInterface(compositor,&IID_ICompositorDesktopInterop,(void **)&desktop));
    if(custom)
    {
        cls.lpfnWndProc=DefWindowProcW;
        cls.hInstance=GetModuleHandleW(NULL);
        cls.lpszClassName=L"SodaTrackerBackdrop";
        cls.hbrBackground=(HBRUSH)GetStockObject(WHITE_BRUSH);
        if(!RegisterClassW(&cls))return 3;
    }
    window=CreateWindowExW(topmost ? WS_EX_TOPMOST : 0,custom ? cls.lpszClassName : L"STATIC",L"Dynamic tracker pixel test",WS_POPUP,10,10,pow2 ? 128 : 160,pow2 ? 64 : 100,NULL,NULL,GetModuleHandleW(NULL),NULL);if(!window)return 3;
    pixel_window=window;
    ShowWindow(window,SW_SHOWNOACTIVATE);
    if(update || custom)UpdateWindow(window);
    check("target",ICompositorDesktopInterop_CreateDesktopWindowTarget(desktop,window,FALSE,&desktop_target));
    check("target interface",IDesktopWindowTarget_QueryInterface(desktop_target,&IID_ICompositionTarget,(void **)&target));
    check("color",ICompositor_CreateColorBrushWithColor(compositor,((struct Color){255,green ? 0 : 255,green ? 255 : 0,0}),&color));
    pixel_color=color;
    check("brush",ICompositionColorBrush_QueryInterface(color,&IID_ICompositionBrush,(void **)&brush));
    check("sprite",ICompositor_CreateSpriteVisual(compositor,&sprite));
    check("visual",ISpriteVisual_QueryInterface(sprite,&IID_IVisual,(void **)&visual));
    check("object",IVisual_QueryInterface(visual,&IID_ICompositionObject,(void **)&object));
    check("size",IVisual_put_Size(visual,((struct Vector2){20,15})));
    check("offset",IVisual_put_Offset(visual,((struct Vector3){0,20,0})));
    check("brush set",ISpriteVisual_put_Brush(sprite,brush));
    if(flat)check("flat initial offset",IVisual_put_Offset(visual,((struct Vector3){40,20,0})));
    else start(compositor,object,L"Offset.X",L"-tracker.Position.X",L"tracker",tracker_object);
    check("root",ICompositionTarget_put_Root(target,visual));
    stage(controller,visual,"INITIAL");
    if(simple)goto detach;
    check("position",IInteractionTracker_get_Position(tracker,&position));printf("INITIAL_POSITION=%g\n",position.X);
    check("resize",ICompositionPropertySet_InsertVector3(layout,size,((struct Vector3){120,20,0})));
    if(flat)check("flat resized offset",IVisual_put_Offset(visual,((struct Vector3){60,20,0})));
    stage(controller,visual,"RESIZED");
    check("zoom",IInteractionTracker_TryUpdateScale(tracker,4,((struct Vector3){0}),&request));
    if(flat)check("flat scaled offset",IVisual_put_Offset(visual,((struct Vector3){30,20,0})));
    stage(controller,visual,"SCALED");
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
    stage(controller,visual,"POSITION");
    start(compositor,tracker_object,L"MinPosition.X",L"1/0",NULL,NULL);
    stage(controller,visual,"INVALID");
    check("closable",IInteractionTracker_QueryInterface(tracker,&IID_IClosable,(void **)&closable));
    check("close",IClosable_Close(closable));check("close again",IClosable_Close(closable));IClosable_Release(closable);
    ICompositionPropertySet_AddRef(layout);refs_after=ICompositionPropertySet_Release(layout);
    printf("LAYOUT_REFS_CLOSED=%lu\n",refs_after);if(candidate && (refs_before!=4||refs_after!=2))return 6;
detach:
    check("detach",ICompositionTarget_put_Root(target,NULL));
    ICompositionObject_Release(object);IVisual_Release(visual);ISpriteVisual_Release(sprite);
    ICompositionBrush_Release(brush);ICompositionColorBrush_Release(color);
    if(tracker_object)ICompositionObject_Release(tracker_object);
    if(tracker)IInteractionTracker_Release(tracker);
    if(layout_object)ICompositionObject_Release(layout_object);
    if(layout)ICompositionPropertySet_Release(layout);
    WindowsDeleteString(size);
    ICompositionTarget_Release(target);IDesktopWindowTarget_Release(desktop_target);ICompositorDesktopInterop_Release(desktop);
    ICompositor_Release(compositor);ICompositorController_Release(controller);DestroyWindow(window);
    if(custom)UnregisterClassW(cls.lpszClassName,cls.hInstance);
    if(queue)IUnknown_Release((IUnknown *)queue);
    RoUninitialize();puts("TRACKER_DONE");return 0;
}
