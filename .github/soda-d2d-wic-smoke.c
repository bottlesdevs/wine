#define COBJMACROS
#include <windows.h>
#include <d2d1.h>
#include <wincodec.h>
#include <stdio.h>

static BOOL pixel_matches(IWICBitmap *bitmap, BYTE red, BYTE green, BYTE blue)
{
    WICRect rect = {0, 0, 1, 1};
    BYTE pixel[4] = {0};
    HRESULT hr = IWICBitmap_CopyPixels(bitmap, &rect, sizeof(pixel), sizeof(pixel), pixel);

    printf("WIC_PIXEL=%08lx rgba=%u,%u,%u,%u\n", (unsigned long)hr,
            pixel[2], pixel[1], pixel[0], pixel[3]);
    return SUCCEEDED(hr) && pixel[2] == red && pixel[1] == green
            && pixel[0] == blue && pixel[3] == 255;
}

int wmain(int argc, WCHAR **argv)
{
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *bitmap = NULL;
    IWICBitmapLock *held = NULL, *denied = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1SolidColorBrush *brush = NULL;
    ID2D1RectangleGeometry *geometry = NULL;
    D2D1_RENDER_TARGET_PROPERTIES properties = {0};
    D2D1_COLOR_F blue = {0, 0, 1, 1}, green = {0, 1, 0, 1};
    D2D1_RECT_F bounds = {0, 0, 2, 2};
    WICRect rect = {0, 0, 2, 2};
    D2D1_TAG first, second;
    HRESULT hr, lock_hr;
    int result = 1;

    if (argc > 2 || (argc == 2 && !_wfreopen(argv[1], L"w", stdout))) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 3;
#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    CHECK(CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            &IID_IWICImagingFactory, (void **)&imaging));
    CHECK(IWICImagingFactory_CreateBitmap(imaging, 2, 2, &GUID_WICPixelFormat32bppPBGRA,
            WICBitmapCacheOnLoad, &bitmap));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory,
            NULL, (void **)&factory));
    CHECK(ID2D1Factory_CreateWicBitmapRenderTarget(factory, bitmap, &properties, &target));
    ID2D1RenderTarget_BeginDraw(target);
    ID2D1RenderTarget_Clear(target, &blue);
    CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
    if (!pixel_matches(bitmap, 0, 0, 255)) goto done;

    CHECK(IWICBitmap_Lock(bitmap, &rect, WICBitmapLockRead, &held));
    lock_hr = IWICBitmap_Lock(bitmap, &rect, WICBitmapLockWrite, &denied);
    printf("HELD_DIRECT_WRITE=%08lx\n", (unsigned long)lock_hr);
    if (lock_hr != WINCODEC_ERR_ALREADYLOCKED) goto done;
    ID2D1RenderTarget_BeginDraw(target);
    ID2D1RenderTarget_SetTags(target, 0x1111, 0x2222);
    ID2D1RenderTarget_Clear(target, &green);
    hr = ID2D1RenderTarget_EndDraw(target, &first, &second);
    printf("WIC_LOCKED_END=%08lx tags=%llx,%llx\n", (unsigned long)hr, first, second);
    if (hr != lock_hr || first != 0x1111 || second != 0x2222) goto done;
    IWICBitmapLock_Release(held);
    held = NULL;
    if (!pixel_matches(bitmap, 0, 0, 255)) goto done;

    ID2D1RenderTarget_BeginDraw(target);
    ID2D1RenderTarget_Clear(target, &green);
    CHECK(ID2D1RenderTarget_EndDraw(target, &first, &second));
    if (first || second || !pixel_matches(bitmap, 0, 255, 0)) goto done;
    printf("WIC_RECOVERY=PASS\n");

    CHECK(ID2D1Factory_CreateRectangleGeometry(factory, &bounds, &geometry));
    CHECK(ID2D1RenderTarget_CreateSolidColorBrush(target, &blue, NULL, &brush));
    CHECK(IWICBitmap_Lock(bitmap, &rect, WICBitmapLockRead, &held));
    ID2D1RenderTarget_BeginDraw(target);
    ID2D1RenderTarget_SetTags(target, 0x3333, 0x4444);
    ID2D1RenderTarget_FillGeometry(target, (ID2D1Geometry *)geometry,
            (ID2D1Brush *)brush, (ID2D1Brush *)brush);
    ID2D1RenderTarget_SetTags(target, 0x5555, 0x6666);
    hr = ID2D1RenderTarget_EndDraw(target, &first, &second);
    printf("WIC_FIRST_ERROR=%08lx tags=%llx,%llx\n", (unsigned long)hr, first, second);
    if (hr != D2DERR_INCOMPATIBLE_BRUSH_TYPES || first != 0x3333 || second != 0x4444) goto done;
    result = 0;
done:
    if (held) IWICBitmapLock_Release(held);
    if (denied) IWICBitmapLock_Release(denied);
    if (brush) ID2D1SolidColorBrush_Release(brush);
    if (geometry) ID2D1RectangleGeometry_Release(geometry);
    if (target) ID2D1RenderTarget_Release(target);
    if (factory) ID2D1Factory_Release(factory);
    if (bitmap) IWICBitmap_Release(bitmap);
    if (imaging) IWICImagingFactory_Release(imaging);
    CoUninitialize();
    printf("RESULT=%s\n", result ? "FAIL" : "PASS");
    return result;
}
