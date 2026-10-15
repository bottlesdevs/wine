#define COBJMACROS
#define INITGUID
#include <stdio.h>
#include "windows.h"
#include "winstring.h"
#include "roapi.h"
#include "objbase.h"
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

struct event_value { struct Vector3 position; FLOAT scale; INT32 request; };
struct test_owner
{
    IInteractionTrackerOwner iface;
    LONG refs,active,max_active,closed,late,same_thread;
    DWORD caller;
    HANDLE started,release;
    IInteractionTrackerValuesChangedArgs *retained;
    CRITICAL_SECTION cs;
    UINT count;
    BOOL bad,deny_marshal,deny_owner,close_on_callback,force_marshal,allow_missing_owner,no_records,skip_metadata;
    IUnknown *marshaler;
    struct event_value events[512];
};

static ULONG WINAPI owner_addref(IInteractionTrackerOwner *iface)
{ return InterlockedIncrement(&((struct test_owner *)iface)->refs); }
static ULONG WINAPI owner_release(IInteractionTrackerOwner *iface)
{ return InterlockedDecrement(&((struct test_owner *)iface)->refs); }
static HRESULT WINAPI owner_query(IInteractionTrackerOwner *iface,REFIID iid,void **out)
{
    struct test_owner *owner=(struct test_owner *)iface;
    if(!out)return E_POINTER;
    *out=NULL;
    if(IsEqualGUID(iid,&IID_IMarshal)&&owner->marshaler)
        return IUnknown_QueryInterface(owner->marshaler,iid,out);
    if(!IsEqualGUID(iid,&IID_IUnknown)&&!IsEqualGUID(iid,&IID_IInspectable)&&!(IsEqualGUID(iid,&IID_IAgileObject)&&!owner->force_marshal)&&
       !(IsEqualGUID(iid,&IID_IInteractionTrackerOwner)&&!owner->deny_owner)&&
       !(IsEqualGUID(iid,&IID_INoMarshal)&&owner->deny_marshal))return E_NOINTERFACE;
    *out=iface;owner_addref(iface);return S_OK;
}
static HRESULT WINAPI owner_iids(IInteractionTrackerOwner *iface,ULONG *count,IID **iids)
{ if(!count||!iids)return E_POINTER;*count=0;*iids=NULL;return S_OK; }
static HRESULT WINAPI owner_name(IInteractionTrackerOwner *iface,HSTRING *value)
{ if(!value)return E_POINTER;*value=NULL;return S_OK; }
static HRESULT WINAPI owner_trust(IInteractionTrackerOwner *iface,TrustLevel *value)
{ if(!value)return E_POINTER;*value=BaseTrust;return S_OK; }

#define OWNER_STATE(name) \
static HRESULT WINAPI owner_##name(IInteractionTrackerOwner *iface,IInteractionTracker *sender, \
        IInteractionTracker##name##Args *args) { return E_NOTIMPL; }
OWNER_STATE(CustomAnimationStateEntered)
OWNER_STATE(IdleStateEntered)
OWNER_STATE(InertiaStateEntered)
OWNER_STATE(InteractingStateEntered)
OWNER_STATE(RequestIgnored)

static void close_tracker(IInteractionTracker *tracker)
{
    IClosable *closable;
    check("closable",IInteractionTracker_QueryInterface(tracker,&IID_IClosable,(void **)&closable));
    check("close",IClosable_Close(closable));IClosable_Release(closable);
}

static HRESULT WINAPI owner_values(IInteractionTrackerOwner *iface,IInteractionTracker *sender,
        IInteractionTrackerValuesChangedArgs *args)
{
    struct test_owner *owner=(struct test_owner *)iface;
    struct event_value value;
    IInteractionTrackerOwner *actual=NULL;
    IUnknown *agile=NULL;
    HSTRING name=NULL;
    IID *iids=NULL;
    ULONG count=0;
    LONG active=InterlockedIncrement(&owner->active),old;

    do{old=owner->max_active;if(old>=active)break;}while(InterlockedCompareExchange(&owner->max_active,active,old)!=old);
    if(owner->caller==GetCurrentThreadId())InterlockedIncrement(&owner->same_thread);
    if(owner->closed)InterlockedIncrement(&owner->late);
    check("event position",IInteractionTrackerValuesChangedArgs_get_Position(args,&value.position));
    check("event scale",IInteractionTrackerValuesChangedArgs_get_Scale(args,&value.scale));
    check("event request",IInteractionTrackerValuesChangedArgs_get_RequestId(args,&value.request));
    check("owner getter",IInteractionTracker_get_Owner(sender,&actual));
    if((actual&&actual!=iface)||(!actual&&!owner->allow_missing_owner))owner->bad=TRUE;
    if(actual)IInteractionTrackerOwner_Release(actual);
    EnterCriticalSection(&owner->cs);
    if(!owner->count&&!owner->skip_metadata)
    {
        check("event agile",IInteractionTrackerValuesChangedArgs_QueryInterface(args,&IID_IAgileObject,(void **)&agile));
        IUnknown_Release(agile);
        check("event iids",IInteractionTrackerValuesChangedArgs_GetIids(args,&count,&iids));
        if(count!=1||!IsEqualGUID(iids,&IID_IInteractionTrackerValuesChangedArgs))owner->bad=TRUE;
        CoTaskMemFree(iids);
        check("event name",IInteractionTrackerValuesChangedArgs_GetRuntimeClassName(args,&name));
        if(wcscmp(WindowsGetStringRawBuffer(name,NULL),RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs))owner->bad=TRUE;
        WindowsDeleteString(name);
        if(IInteractionTrackerValuesChangedArgs_get_Scale(args,NULL)!=E_POINTER||
           IInteractionTrackerValuesChangedArgs_get_Position(args,NULL)!=E_POINTER||
           IInteractionTrackerValuesChangedArgs_get_RequestId(args,NULL)!=E_POINTER)owner->bad=TRUE;
    }
    if(!owner->no_records)
    {
        if(owner->count<512)owner->events[owner->count]=value;
        else owner->bad=TRUE;
    }
    ++owner->count;
    LeaveCriticalSection(&owner->cs);
    if(owner->started&&owner->count==1)
    {
        owner->retained=args;IInteractionTrackerValuesChangedArgs_AddRef(args);SetEvent(owner->started);
        if(WaitForSingleObject(owner->release,10000)!=WAIT_OBJECT_0)ExitProcess(11);
    }
    if(owner->close_on_callback)
    {
        owner->close_on_callback=FALSE;
        close_tracker(sender);
    }
    InterlockedDecrement(&owner->active);
    return S_OK;
}
static const IInteractionTrackerOwnerVtbl owner_vtbl=
{
    owner_query,owner_addref,owner_release,owner_iids,owner_name,owner_trust,
    owner_CustomAnimationStateEntered,owner_IdleStateEntered,owner_InertiaStateEntered,
    owner_InteractingStateEntered,owner_RequestIgnored,owner_values
};

static void owner_init(struct test_owner *owner)
{
    memset(owner,0,sizeof(*owner));owner->iface.lpVtbl=&owner_vtbl;owner->refs=1;
    InitializeCriticalSection(&owner->cs);
}
static void wait_events(struct test_owner *owner,UINT expected)
{
    DWORD deadline=GetTickCount()+10000;
    UINT count;
    do
    {
        EnterCriticalSection(&owner->cs);count=owner->count;LeaveCriticalSection(&owner->cs);
        if(count>=expected)return;
        Sleep(10);
    }while((INT32)(deadline-GetTickCount())>0);
    printf("EVENT_TIMEOUT=%u EXPECTED=%u\n",count,expected);ExitProcess(4);
}
static void owner_done(struct test_owner *owner)
{
    DWORD deadline=GetTickCount()+5000;
    while((owner->refs!=1||owner->active)&&(INT32)(deadline-GetTickCount())>0)Sleep(10);
    if(owner->refs!=1||owner->active||owner->max_active>1||owner->bad)ExitProcess(5);
    if(owner->marshaler)IUnknown_Release(owner->marshaler);
    DeleteCriticalSection(&owner->cs);
}
static void expect(struct test_owner *owner,UINT index,INT32 request,FLOAT x,FLOAT y,FLOAT z,FLOAT scale)
{
    struct event_value *value=&owner->events[index];
    if(value->request!=request||value->position.X!=x||value->position.Y!=y||value->position.Z!=z||value->scale!=scale)
    {
        printf("EVENT_MISMATCH=%u REQUEST=%d XYZ=%g,%g,%g SCALE=%g\n",index,value->request,value->position.X,value->position.Y,value->position.Z,value->scale);
        ExitProcess(6);
    }
}
static void configure_tracker(IInteractionTracker *tracker)
{
    check("min position",IInteractionTracker_put_MinPosition(tracker,((struct Vector3){-10000,-10000,-10000})));
    check("max position",IInteractionTracker_put_MaxPosition(tracker,((struct Vector3){10000,10000,10000})));
    check("min scale",IInteractionTracker_put_MinScale(tracker,0.1f));
    check("max scale",IInteractionTracker_put_MaxScale(tracker,4));
}
static DWORD WINAPI produce(void *data)
{
    IInteractionTracker *tracker=data;
    INT32 request;
    UINT i;
    check("producer initialize",RoInitialize(RO_INIT_MULTITHREADED));
    for(i=0;i<100;++i)check("producer position",IInteractionTracker_TryUpdatePositionBy(tracker,((struct Vector3){1,1,1}),&request));
    RoUninitialize();return 0;
}


static DWORD WINAPI close_from_thread(void *data)
{
    check("close thread initialize",RoInitialize(RO_INIT_MULTITHREADED));
    close_tracker(data);RoUninitialize();return 0;
}
static void test_close_snapshot(IInteractionTrackerStatics *factory,ICompositor *compositor)
{
    struct test_owner owner;
    IInteractionTracker *tracker;
    INT32 request;
    FLOAT retained;
    UINT i;
    DWORD deadline;
    HANDLE closing;
    LONG retained_refs;

    owner_init(&owner);owner.caller=GetCurrentThreadId();owner.skip_metadata=TRUE;owner.allow_missing_owner=TRUE;
    owner.started=CreateEventW(NULL,TRUE,FALSE,NULL);owner.release=CreateEventW(NULL,TRUE,FALSE,NULL);
    check("close tracker",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&owner.iface,&tracker));
    configure_tracker(tracker);
    check("close first scale",IInteractionTracker_TryUpdateScale(tracker,0.5f,((struct Vector3){0}),&request));
    if(WaitForSingleObject(owner.started,5000)!=WAIT_OBJECT_0)ExitProcess(12);
    for(i=0;i<20;++i)check("close queued scale",IInteractionTracker_TryUpdateScale(tracker,1.0f+i*0.01f,((struct Vector3){0}),&request));
    check("retained queued snapshot",IInteractionTrackerValuesChangedArgs_get_Scale(owner.retained,&retained));
    if(retained!=0.5f)ExitProcess(13);
    closing=CreateThread(NULL,0,close_from_thread,tracker,0,NULL);if(!closing)ExitProcess(14);
    WaitForSingleObject(closing,300);InterlockedExchange(&owner.closed,1);SetEvent(owner.release);
    if(WaitForSingleObject(closing,5000)!=WAIT_OBJECT_0)ExitProcess(14);
    CloseHandle(closing);
    deadline=GetTickCount()+5000;
    while((owner.refs!=1||owner.active)&&(INT32)(deadline-GetTickCount())>0)Sleep(10);
    retained_refs=owner.refs;
    check("retained after close",IInteractionTrackerValuesChangedArgs_get_Scale(owner.retained,&retained));
    if(retained!=0.5f)ExitProcess(13);
    IInteractionTrackerValuesChangedArgs_Release(owner.retained);
    printf("OWNER_CLOSE_CALLS=%u LATE=%ld REFS_WITH_ARGS=%ld SAME_THREAD=%ld\n",owner.count,owner.late,retained_refs,owner.same_thread);
    IInteractionTracker_Release(tracker);CloseHandle(owner.started);CloseHandle(owner.release);
    owner_done(&owner);
    if(owner.late||owner.same_thread||retained_refs!=1)ExitProcess(15);
    puts("OWNER_CLOSE_SNAPSHOT_PASS");
}

struct churn_context
{
    IInteractionTrackerStatics *factory;
    IInteractionTrackerStatics2 *bindings;
    ICompositor *compositor;
    IInteractionTracker *root;
    struct test_owner *owner;
};
static DWORD WINAPI churn_peers(void *data)
{
    struct churn_context *context=data;
    IInteractionTracker *peer;
    UINT i;
    check("churn initialize",RoInitialize(RO_INIT_MULTITHREADED));
    for(i=0;i<1000;++i)
    {
        check("churn create",IInteractionTrackerStatics_CreateWithOwner(context->factory,context->compositor,&context->owner->iface,&peer));
        configure_tracker(peer);
        check("churn bind",IInteractionTrackerStatics2_SetBindingMode(context->bindings,context->root,peer,
                InteractionBindingAxisModes_PositionX|InteractionBindingAxisModes_PositionY|InteractionBindingAxisModes_Scale));
        if(i%2)close_tracker(peer);
        IInteractionTracker_Release(peer);
    }
    RoUninitialize();return 0;
}
static DWORD WINAPI churn_updates(void *data)
{
    struct churn_context *context=data;
    UINT i;
    INT32 request;
    check("churn updates initialize",RoInitialize(RO_INIT_MULTITHREADED));
    for(i=0;i<4000;++i)
        check("churn update",IInteractionTracker_TryUpdatePosition(context->root,((struct Vector3){i%31,i%17,0}),&request));
    RoUninitialize();return 0;
}
int main(int argc,char **argv)
{
    struct test_owner a,b,c,bad,foreign,stress;
    struct churn_context churn;
    IInspectable *instance;
    ICompositorController *controller;
    ICompositor *compositor;
    IInteractionTrackerStatics *factory;
    IInteractionTrackerStatics2 *bindings;
    IInteractionTracker *root,*peer,*closing,*rejected;
    HSTRING name;
    HRESULT hr;
    HANDLE threads[4];
    UINT i;
    INT32 request;

    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
    check("factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
    check("bindings",IInteractionTrackerStatics_QueryInterface(factory,&IID_IInteractionTrackerStatics2,(void **)&bindings));
    test_close_snapshot(factory,compositor);
    if(argc>1&&!strcmp(argv[1],"close"))goto done;
    owner_init(&bad);bad.deny_marshal=TRUE;rejected=(IInteractionTracker *)1;
    hr=IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&bad.iface,&rejected);
    if(SUCCEEDED(hr)||rejected||bad.refs!=1)return 7;
    bad.deny_marshal=FALSE;bad.deny_owner=TRUE;rejected=(IInteractionTracker *)1;
    hr=IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&bad.iface,&rejected);
    if(hr!=E_NOINTERFACE||rejected||bad.refs!=1)return 7;
    owner_done(&bad);puts("OWNER_CONSTRUCTOR_REJECTION_PASS");

    owner_init(&a);owner_init(&b);
    check("root",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&a.iface,&root));
    check("peer",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&b.iface,&peer));
    configure_tracker(root);configure_tracker(peer);
    check("bind",IInteractionTrackerStatics2_SetBindingMode(bindings,root,peer,InteractionBindingAxisModes_PositionX|InteractionBindingAxisModes_Scale));
    check("position",IInteractionTracker_TryUpdatePosition(root,((struct Vector3){3,4,5}),&request));
    wait_events(&a,1);wait_events(&b,1);expect(&a,0,1,3,4,5,1);expect(&b,0,0,3,0,0,1);
    check("scale",IInteractionTracker_TryUpdateScale(root,0.5f,((struct Vector3){0}),&request));
    wait_events(&a,2);wait_events(&b,2);expect(&a,1,2,3,4,5,0.5f);expect(&b,1,0,3,0,0,0.5f);
    for(i=0;i<4;++i){threads[i]=CreateThread(NULL,0,produce,root,0,NULL);if(!threads[i])return 8;}
    if(WaitForMultipleObjects(4,threads,TRUE,15000)!=WAIT_OBJECT_0)return 8;
    for(i=0;i<4;++i)CloseHandle(threads[i]);
    wait_events(&a,402);wait_events(&b,402);
    for(i=0;i<402;++i)if(a.events[i].request!=(INT32)i+1||b.events[i].request)return 9;
    expect(&a,401,402,403,404,405,0.5f);expect(&b,401,0,403,0,0,0.5f);
    close_tracker(root);close_tracker(peer);IInteractionTracker_Release(root);IInteractionTracker_Release(peer);
    owner_done(&a);owner_done(&b);puts("OWNER_400_CONCURRENT_REQUESTS_PEER_ORDER_PASS");

    owner_init(&c);c.close_on_callback=TRUE;
    check("reentrant tracker",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&c.iface,&closing));
    configure_tracker(closing);
    check("reentrant scale",IInteractionTracker_TryUpdateScale(closing,0.75f,((struct Vector3){0}),&request));
    wait_events(&c,1);owner_done(&c);IInteractionTracker_Release(closing);
    puts("OWNER_REENTRANT_CLOSE_PASS");
    owner_init(&foreign);foreign.force_marshal=TRUE;
    check("foreign marshaler",CoCreateFreeThreadedMarshaler((IUnknown *)&foreign.iface,&foreign.marshaler));
    check("foreign tracker",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&foreign.iface,&root));
    configure_tracker(root);
    check("foreign position",IInteractionTracker_TryUpdatePosition(root,((struct Vector3){7,8,9}),&request));
    wait_events(&foreign,1);expect(&foreign,0,1,7,8,9,1);
    close_tracker(root);IInteractionTracker_Release(root);owner_done(&foreign);
    puts("OWNER_FOREIGN_MARSHALER_PASS");

    owner_init(&stress);stress.no_records=TRUE;stress.allow_missing_owner=TRUE;
    check("churn root",IInteractionTrackerStatics_CreateWithOwner(factory,compositor,&stress.iface,&root));
    configure_tracker(root);churn=(struct churn_context){factory,bindings,compositor,root,&stress};
    threads[0]=CreateThread(NULL,0,churn_peers,&churn,0,NULL);threads[1]=CreateThread(NULL,0,churn_updates,&churn,0,NULL);
    if(!threads[0]||!threads[1]||WaitForMultipleObjects(2,threads,TRUE,20000)!=WAIT_OBJECT_0)return 10;
    CloseHandle(threads[0]);CloseHandle(threads[1]);close_tracker(root);IInteractionTracker_Release(root);owner_done(&stress);
    puts("OWNER_1000_PEER_LIFETIMES_4000_UPDATES_PASS");
done:
    IInteractionTrackerStatics2_Release(bindings);IInteractionTrackerStatics_Release(factory);
    ICompositor_Release(compositor);ICompositorController_Release(controller);RoUninitialize();
    puts("OWNER_EVENTS_DONE");return 0;
}
/* Private delivery probe using the published Windows SDK ABI. */
