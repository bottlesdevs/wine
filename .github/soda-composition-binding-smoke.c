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

static void expect_scale(IInteractionTracker *tracker,FLOAT expected)
{
    FLOAT value;
    check("get scale",IInteractionTracker_get_Scale(tracker,&value));
    if(value!=expected){printf("SCALE_MISMATCH=%g EXPECTED=%g\n",value,expected);ExitProcess(4);}
}

static void update_scale(IInteractionTracker *tracker,FLOAT value)
{
    INT32 request;
    check("update scale",IInteractionTracker_TryUpdateScale(tracker,value,((struct Vector3){0}),&request));
}


static void expect_position(IInteractionTracker *tracker,FLOAT x,FLOAT y,FLOAT z)
{
    struct Vector3 value;
    check("get position",IInteractionTracker_get_Position(tracker,&value));
    if(value.X!=x||value.Y!=y||value.Z!=z)
    {
        printf("POSITION_MISMATCH=%g,%g,%g EXPECTED=%g,%g,%g\n",value.X,value.Y,value.Z,x,y,z);
        ExitProcess(4);
    }
}

static void test_position_bindings(IInteractionTrackerStatics *factory,IInteractionTrackerStatics2 *bindings,ICompositor *compositor)
{
    IInteractionTracker *trackers[5];
    IInteractionTracker5 *options;
    IClosable *closable;
    INT32 request;
    UINT i;

    for(i=0;i<5;++i)check("position create",IInteractionTrackerStatics_Create(factory,compositor,&trackers[i]));
    check("bind X",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[1],InteractionBindingAxisModes_PositionX));
    check("bind distinct Y",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[1],trackers[2],InteractionBindingAxisModes_PositionY));
    check("bind Y",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[3],InteractionBindingAxisModes_PositionY));
    check("scale only",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[4],InteractionBindingAxisModes_Scale));
    check("position update",IInteractionTracker_TryUpdatePosition(trackers[0],((struct Vector3){20,30,4}),&request));
    expect_position(trackers[0],20,30,4);expect_position(trackers[1],20,0,0);
    expect_position(trackers[2],0,0,0);expect_position(trackers[3],0,30,0);expect_position(trackers[4],0,0,0);
    check("reverse position",IInteractionTracker_TryUpdatePosition(trackers[1],((struct Vector3){10,40,2}),&request));
    if(request!=1)ExitProcess(8);
    expect_position(trackers[0],10,30,4);expect_position(trackers[1],10,40,2);expect_position(trackers[2],0,40,0);
    check("relative position",IInteractionTracker_TryUpdatePositionBy(trackers[0],((struct Vector3){5,-7,9}),&request));
    expect_position(trackers[0],15,23,13);expect_position(trackers[1],15,40,2);expect_position(trackers[3],0,23,0);
    check("extend axes",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[1],InteractionBindingAxisModes_PositionX|InteractionBindingAxisModes_PositionY));
    check("position options",IInteractionTracker_QueryInterface(trackers[0],&IID_IInteractionTracker5,(void **)&options));
    check("option update",IInteractionTracker5_TryUpdatePositionWithOption(options,((struct Vector3){50,60,7}),InteractionTrackerClampingOption_Auto,InteractionTrackerPositionUpdateOption_Default,&request));
    IInteractionTracker5_Release(options);
    expect_position(trackers[0],50,60,7);expect_position(trackers[1],50,60,2);expect_position(trackers[2],0,60,0);expect_position(trackers[3],0,60,0);
    check("position cycle",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[2],InteractionBindingAxisModes_PositionX));
    check("cycle update",IInteractionTracker_TryUpdatePosition(trackers[1],((struct Vector3){70,80,3}),&request));
    expect_position(trackers[0],70,80,7);expect_position(trackers[2],70,80,0);expect_position(trackers[3],0,80,0);
    check("position unbind",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[1],InteractionBindingAxisModes_None));
    check("distinct component",IInteractionTracker_TryUpdatePosition(trackers[0],((struct Vector3){90,100,5}),&request));
    expect_position(trackers[1],70,80,3);expect_position(trackers[2],90,80,0);expect_position(trackers[3],0,100,0);
    check("position closable",IInteractionTracker_QueryInterface(trackers[2],&IID_IClosable,(void **)&closable));
    check("position close",IClosable_Close(closable));IClosable_Release(closable);
    check("closed peer update",IInteractionTracker_TryUpdatePosition(trackers[0],((struct Vector3){95,105,6}),&request));
    expect_position(trackers[2],90,80,0);
    for(i=0;i<5;++i){expect_scale(trackers[i],1);IInteractionTracker_Release(trackers[i]);}
    puts("BINDING_POSITION_AXES_RELATIVE_OPTIONS_UNBIND_CLOSE_PASS");
}

struct stress_context
{
    IInteractionTrackerStatics *factory;
    IInteractionTrackerStatics2 *bindings;
    ICompositor *compositor;
    IInteractionTracker *root;
};

static DWORD WINAPI stress_update(void *data)
{
    struct stress_context *context=data;
    UINT i;
    check("worker initialize",RoInitialize(RO_INIT_MULTITHREADED));
    for(i=0;i<4000;++i)
    {
        INT32 request;
        update_scale(context->root,0.5f+(i%10)*0.1f);
        check("stress position",IInteractionTracker_TryUpdatePosition(context->root,((struct Vector3){i%31,i%17,0}),&request));
        check("stress relative",IInteractionTracker_TryUpdatePositionBy(context->root,((struct Vector3){1,-1,0}),&request));
    }
    RoUninitialize();return 0;
}

static DWORD WINAPI stress_bind(void *data)
{
    struct stress_context *context=data;
    IInteractionTracker *peer;
    IClosable *closable;
    UINT i;

    check("worker initialize",RoInitialize(RO_INIT_MULTITHREADED));
    for(i=0;i<1000;++i)
    {
        check("stress create",IInteractionTrackerStatics_Create(context->factory,context->compositor,&peer));
        check("stress bind",IInteractionTrackerStatics2_SetBindingMode(context->bindings,context->root,peer,InteractionBindingAxisModes_Scale|InteractionBindingAxisModes_PositionX|InteractionBindingAxisModes_PositionY));
        if(i%2)
        {
            check("stress closable",IInteractionTracker_QueryInterface(peer,&IID_IClosable,(void **)&closable));
            check("stress close",IClosable_Close(closable));IClosable_Release(closable);
        }
        IInteractionTracker_Release(peer);
    }
    RoUninitialize();return 0;
}

int main(void)
{
    IInspectable *instance;
    ICompositorController *controller;
    ICompositor *compositor;
    IInteractionTrackerStatics *factory;
    IInteractionTrackerStatics2 *bindings;
    IInteractionTracker *trackers[5],*chain[256];
    IClosable *closable;
    HSTRING name;
    INT32 request;
    UINT i;
    HANDLE threads[2];
    struct stress_context stress;

    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
    check("factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
    check("bindings",IInteractionTrackerStatics_QueryInterface(factory,&IID_IInteractionTrackerStatics2,(void **)&bindings));
    test_position_bindings(factory,bindings,compositor);
    for(i=0;i<5;++i)check("create",IInteractionTrackerStatics_Create(factory,compositor,&trackers[i]));
    check("bind01",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[1],InteractionBindingAxisModes_Scale));
    check("bind12",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[1],trackers[2],InteractionBindingAxisModes_Scale|InteractionBindingAxisModes_PositionX));
    check("bind20",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[2],trackers[0],InteractionBindingAxisModes_Scale));
    check("position only",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[2],trackers[3],InteractionBindingAxisModes_PositionX));
    check("separate scale",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[3],trackers[4],InteractionBindingAxisModes_Scale));
    update_scale(trackers[0],0.5f);
    for(i=0;i<3;++i)expect_scale(trackers[i],0.5f);
    for(i=3;i<5;++i)expect_scale(trackers[i],1.0f);
    update_scale(trackers[2],1.45f);
    for(i=0;i<3;++i)expect_scale(trackers[i],1.45f);
    check("peer request",IInteractionTracker_TryUpdateScale(trackers[1],2.0f,((struct Vector3){0}),&request));
    if(request!=1)return 5;
    check("remove01",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[0],trackers[1],InteractionBindingAxisModes_None));
    update_scale(trackers[0],0.75f);
    for(i=0;i<3;++i)expect_scale(trackers[i],0.75f);
    check("remove12",IInteractionTrackerStatics2_SetBindingMode(bindings,trackers[1],trackers[2],InteractionBindingAxisModes_None));
    update_scale(trackers[0],1.25f);
    expect_scale(trackers[0],1.25f);expect_scale(trackers[2],1.25f);expect_scale(trackers[1],0.75f);
    check("close peer",IInteractionTracker_QueryInterface(trackers[2],&IID_IClosable,(void **)&closable));
    check("close",IClosable_Close(closable));IClosable_Release(closable);
    update_scale(trackers[0],0.625f);expect_scale(trackers[2],1.25f);
    for(i=0;i<5;++i)IInteractionTracker_Release(trackers[i]);
    puts("BINDING_CYCLE_AXIS_UNBIND_CLOSE_PASS");

    for(i=0;i<256;++i)
    {
        check("chain create",IInteractionTrackerStatics_Create(factory,compositor,&chain[i]));
        if(i)check("chain bind",IInteractionTrackerStatics2_SetBindingMode(bindings,chain[i-1],chain[i],InteractionBindingAxisModes_Scale));
    }
    check("chain cycle",IInteractionTrackerStatics2_SetBindingMode(bindings,chain[255],chain[0],InteractionBindingAxisModes_Scale));
    update_scale(chain[0],0.625f);
    for(i=0;i<256;++i)expect_scale(chain[i],0.625f);
    puts("BINDING_256_NODE_CYCLE_PASS");
    for(i=1;i<256;++i)check("chain position bind",IInteractionTrackerStatics2_SetBindingMode(bindings,chain[i-1],chain[i],InteractionBindingAxisModes_PositionX));
    check("chain position cycle",IInteractionTrackerStatics2_SetBindingMode(bindings,chain[255],chain[0],InteractionBindingAxisModes_PositionX));
    check("chain position update",IInteractionTracker_TryUpdatePosition(chain[0],((struct Vector3){17,9,4}),&request));
    expect_position(chain[0],17,9,4);
    for(i=1;i<256;++i)expect_position(chain[i],17,0,0);
    puts("BINDING_256_NODE_POSITION_CYCLE_PASS");
    for(i=1;i<256;++i)IInteractionTracker_Release(chain[i]);
    stress=(struct stress_context){factory,bindings,compositor,chain[0]};
    threads[0]=CreateThread(NULL,0,stress_update,&stress,0,NULL);
    threads[1]=CreateThread(NULL,0,stress_bind,&stress,0,NULL);
    if(!threads[0]||!threads[1]||WaitForMultipleObjects(2,threads,TRUE,15000)!=WAIT_OBJECT_0)return 6;
    CloseHandle(threads[0]);CloseHandle(threads[1]);
    update_scale(chain[0],0.875f);expect_scale(chain[0],0.875f);
    IInteractionTracker_Release(chain[0]);
    puts("BINDING_4000_UPDATES_1000_PEER_LIFETIMES_PASS");
    IInteractionTrackerStatics2_Release(bindings);IInteractionTrackerStatics_Release(factory);
    ICompositor_Release(compositor);ICompositorController_Release(controller);RoUninitialize();
    puts("BINDING_DONE");return 0;
}
