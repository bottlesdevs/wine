#define main collector_main
#include "../native/debugger.c"
#undef main

#ifdef EAGLE_LEGACY_FRAME_CACHE
#define invalidate_frames(handle, base) invalidate_frames()
#endif

static void cached(unsigned index, uintptr_t handle, DWORD64 base)
{
    frame_cache[index].handle = (HANDLE)handle;
    frame_cache[index].address = base + 0x100;
    frame_cache[index].has_module = !!base;
    frame_cache[index].module.BaseOfImage = base;
}

int main(void)
{
    cached(0, 1, 0x100000);
    cached(1, 1, 0x200000);
    cached(2, 2, 0x100000);
    cached(3, 1, 0);
    cached(4, 2, 0);
    invalidate_frames((HANDLE)1, 0x200000);
    if (!frame_cache[0].handle || frame_cache[1].handle || !frame_cache[2].handle ||
        frame_cache[3].handle || !frame_cache[4].handle) return 1;

    cached(1, 1, 0x200000);
    invalidate_frames((HANDLE)1, 0x100000);
    if (frame_cache[0].handle || !frame_cache[1].handle || !frame_cache[2].handle) return 2;

    invalidate_frames((HANDLE)1, 0);
    if (frame_cache[1].handle || !frame_cache[2].handle || !frame_cache[4].handle) return 3;
    invalidate_frames((HANDLE)2, 0);
    if (frame_cache[2].handle || frame_cache[4].handle) return 4;

    cached(0, 1, 0x100000);
    invalidate_frames((HANDLE)1, 0x100000);
    cached(0, 1, 0x300000);
    invalidate_frames((HANDLE)1, 0x100000);
    if (!frame_cache[0].handle || frame_cache[0].module.BaseOfImage != 0x300000) return 5;
    puts("frame cache invalidation passed");
    return 0;
}
