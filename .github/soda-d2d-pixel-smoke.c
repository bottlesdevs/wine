#define COBJMACROS
#include <windows.h>
#include <d2d1_1.h>
#include <wincodec.h>
#include <stdio.h>
#include <math.h>

int main(void)
{
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *output = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1DeviceContext *context = NULL;
    ID2D1Bitmap *bitmap = NULL;
    ID2D1SolidColorBrush *brush = NULL;
    D2D1_RENDER_TARGET_PROPERTIES props = {0};
    D2D1_BITMAP_PROPERTIES bitmap_props = {{DXGI_FORMAT_B8G8R8A8_UNORM,
            D2D1_ALPHA_MODE_PREMULTIPLIED}, 96, 96};
    D2D1_SIZE_U size = {20, 20};
    D2D1_RECT_F rect = {0, 0, 40, 40}, small = {0, 0, 10, 10}, bounds;
    D2D1_RECT_F crop = {5, 0, 15, 20};
    D2D1_RECT_F outside = {30, 0, 40, 20};
    D2D1_POINT_2F offset = {4, 0};
    D2D1_COLOR_F white = {1, 1, 1, 1}, black = {0, 0, 0, 1};
    WICRect row = {0, 5, 64, 1};
    DWORD source[400], pixels[64];
    float dpis[] = {72, 96, 300};
    unsigned int i, mode, x, y, failures = 0;
    HRESULT hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            &IID_IWICImagingFactory, (void **)&imaging));
    CHECK(IWICImagingFactory_CreateBitmap(imaging, 64, 64, &GUID_WICPixelFormat32bppPBGRA,
            WICBitmapCacheOnLoad, &output));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory,
            NULL, (void **)&factory));
    CHECK(ID2D1Factory_CreateWicBitmapRenderTarget(factory, output, &props, &target));
    CHECK(ID2D1RenderTarget_QueryInterface(target, &IID_ID2D1DeviceContext, (void **)&context));
    CHECK(ID2D1RenderTarget_CreateSolidColorBrush(target, &black, NULL, &brush));
    for (mode = 0; mode < 2; ++mode)
    {
        ID2D1RenderTarget_SetDpi(target, 144, 144);
        ID2D1DeviceContext_SetUnitMode(context, mode);
        ID2D1RenderTarget_BeginDraw(target);
        ID2D1RenderTarget_Clear(target, &white);
        ID2D1RenderTarget_FillRectangle(target, &small, (ID2D1Brush *)brush);
        CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
        CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 64 && pixels[x] == 0xff000000; ++x) {}
        printf("CONTEXT mode=%u dpi=144 width=%u expected=%u\n", mode, x, mode ? 10 : 15);
        if (x != (mode ? 10 : 15)) ++failures;
        ID2D1RenderTarget_BeginDraw(target);
        ID2D1RenderTarget_Clear(target, &white);
        ID2D1RenderTarget_PushAxisAlignedClip(target, &small, D2D1_ANTIALIAS_MODE_ALIASED);
        ID2D1RenderTarget_FillRectangle(target, &rect, (ID2D1Brush *)brush);
        ID2D1RenderTarget_PopAxisAlignedClip(target);
        CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
        CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 64 && pixels[x] == 0xff000000; ++x) {}
        printf("CLIP mode=%u dpi=144 width=%u expected=%u\n", mode, x, mode ? 10 : 15);
        if (x != (mode ? 10 : 15)) ++failures;
    }
    for (y = 0; y < 20; ++y)
        for (x = 0; x < 20; ++x) source[y * 20 + x] = x < 10 ? 0xffff0000 : 0xff0000ff;
    ID2D1RenderTarget_SetDpi(target, 96, 96);
    for (mode = 0; mode < 2; ++mode)
        for (i = 0; i < 3; ++i)
        {
            bitmap_props.dpiX = bitmap_props.dpiY = dpis[i];
            CHECK(ID2D1RenderTarget_CreateBitmap(target, size, source, 80, &bitmap_props, &bitmap));
            ID2D1DeviceContext_SetUnitMode(context, mode);
            CHECK(ID2D1DeviceContext_GetImageLocalBounds(context, (ID2D1Image *)bitmap, &bounds));
            ID2D1RenderTarget_BeginDraw(target);
            ID2D1RenderTarget_Clear(target, &white);
            ID2D1RenderTarget_DrawBitmap(target, bitmap, &rect, 1,
                    D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR, NULL);
            CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
            CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
            printf("BITMAP mode=%u dpi=%.0f samples=%08lx,%08lx,%08lx\n",
                    mode, dpis[i], pixels[10], pixels[30], pixels[45]);
            if (pixels[10] != 0xffff0000 || pixels[30] != 0xff0000ff || pixels[45] != 0xffffffff)
                ++failures;
            ID2D1RenderTarget_BeginDraw(target);
            ID2D1RenderTarget_Clear(target, &white);
            ID2D1DeviceContext_DrawImage(context, (ID2D1Image *)bitmap, NULL, NULL,
                    D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, D2D1_COMPOSITE_MODE_SOURCE_OVER);
            CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
            CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
            for (x = 0; x < 64 && pixels[x] != 0xffffffff; ++x) {}
            printf("DRAWIMAGE mode=%u dpi=%.0f width=%u bounds=%.3f\n", mode, dpis[i], x,
                    bounds.right - bounds.left);
            if (fabsf((bounds.right - bounds.left) - (mode ? 20.0f : 20.0f * 96.0f / dpis[i])) > 0.01f)
                ++failures;
            if (x != (unsigned int)floorf((mode ? 20.0f : 20.0f * 96.0f / dpis[i]) + 0.5f))
                ++failures;
            if (mode == D2D1_UNIT_MODE_PIXELS)
            {
                ID2D1RenderTarget_BeginDraw(target);
                ID2D1RenderTarget_Clear(target, &white);
                ID2D1DeviceContext_DrawImage(context, (ID2D1Image *)bitmap, &offset, &crop,
                        D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, D2D1_COMPOSITE_MODE_SOURCE_OVER);
                CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
                CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
                printf("CROP dpi=%.0f samples=%08lx,%08lx,%08lx,%08lx,%08lx\n",
                        dpis[i], pixels[3], pixels[4], pixels[8], pixels[9], pixels[14]);
                if (pixels[3] != 0xffffffff || pixels[4] != 0xffff0000 || pixels[8] != 0xffff0000
                        || pixels[9] != 0xff0000ff || pixels[13] != 0xff0000ff || pixels[14] != 0xffffffff)
                    ++failures;
                ID2D1RenderTarget_BeginDraw(target);
                ID2D1RenderTarget_Clear(target, &white);
                ID2D1DeviceContext_DrawImage(context, (ID2D1Image *)bitmap, NULL, &outside,
                        D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, D2D1_COMPOSITE_MODE_SOURCE_OVER);
                CHECK(ID2D1RenderTarget_EndDraw(target, NULL, NULL));
                CHECK(IWICBitmap_CopyPixels(output, &row, sizeof(pixels), sizeof(pixels), (BYTE *)pixels));
                for (x = 0; x < 64 && pixels[x] == 0xffffffff; ++x) {}
                printf("OUTSIDE dpi=%.0f unchanged=%u\n", dpis[i], x);
                if (x != 64) ++failures;
            }
            ID2D1Bitmap_Release(bitmap);
            bitmap = NULL;
        }
    result = failures ? 1 : 0;
done:
    if (bitmap) ID2D1Bitmap_Release(bitmap);
    if (brush) ID2D1SolidColorBrush_Release(brush);
    if (context) IUnknown_Release((IUnknown *)context);
    if (target) ID2D1RenderTarget_Release(target);
    if (factory) ID2D1Factory_Release(factory);
    if (output) IWICBitmap_Release(output);
    if (imaging) IWICImagingFactory_Release(imaging);
    CoUninitialize();
    printf("RESULT=%s\n", result ? "FAIL" : "PASS");
    return result;
}
