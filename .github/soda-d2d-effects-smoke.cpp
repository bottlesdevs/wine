#include <windows.h>
#include <d2d1_1.h>
#include <d2d1effects.h>
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
    D2D1_RENDER_TARGET_PROPERTIES props = {};
    D2D1_BITMAP_PROPERTIES bitmap_props = {{DXGI_FORMAT_B8G8R8A8_UNORM,
            D2D1_ALPHA_MODE_PREMULTIPLIED}, 96, 96};
    D2D1_SIZE_U size = {20, 20};
    D2D1_RECT_F rect = {40, 0, 42, 2};
    D2D1_POINT_2F offset = {12, 12};
    D2D1_VECTOR_4F tint = {0.25f, 0.5f, 1.0f, 0.5f};
    D2D1_COLOR_F white = {1, 1, 1, 1}, black = {0, 0, 0, 1};
    WICRect row = {0, 0, 64, 64};
    DWORD source[400], pixels[4096];
    ID2D1Effect *effect = NULL;
    ID2D1Image *image = NULL;
    D2D1_RECT_F bounds = {}, shape = {0, 0, 24, 24};
    ID2D1CommandList *commands = NULL;
    ID2D1Image *saved = NULL;
    D2D1_LAYER_PARAMETERS1 layer = {};
    D2D1_MATRIX_5X4_F matrix = {};
    unsigned int i, x, failures = 0;
    HRESULT hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory, (void **)&imaging));
    CHECK(imaging->CreateBitmap(64, 64, GUID_WICPixelFormat32bppPBGRA,
            WICBitmapCacheOnLoad, &output));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, IID_ID2D1Factory,
            NULL, (void **)&factory));
    CHECK(factory->CreateWicBitmapRenderTarget(output, &props, &target));
    CHECK(target->QueryInterface(IID_ID2D1DeviceContext, (void **)&context));
    CHECK(target->CreateSolidColorBrush(&black, NULL, &brush));
    layer.contentBounds = D2D1_RECT_F{4, 4, 20, 20};
    layer.maskTransform = D2D1_MATRIX_3X2_F{1, 0, 0, 1, 0, 0};
    layer.opacity = 0.5f;
    matrix._11 = matrix._22 = matrix._33 = 1.0f;
    matrix._44 = 0.5f;
    for (i = 0; i < 4; ++i)
    {
        float dpi = i >= 2 ? 144.0f : 96.0f;
        float scale = i % 2 ? 1.0f : dpi / 96;
        unsigned int differences = 0;
        context->SetDpi(dpi, dpi);
        context->SetUnitMode(i % 2 ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        context->GetTarget(&saved);
        CHECK(context->CreateCommandList(&commands));
        context->SetTarget(commands);
        context->BeginDraw();
        context->PushLayer(&layer, NULL);
        context->FillRectangle(&shape, brush);
        context->FillRectangle(&shape, brush);
        context->PopLayer();
        CHECK(context->EndDraw());
        CHECK(commands->Close());
        context->SetTarget(saved);
        saved->Release(); saved = NULL;
        CHECK(context->CreateEffect(CLSID_D2D1ColorMatrix, &effect));
        CHECK(effect->SetValue(D2D1_COLORMATRIX_PROP_COLOR_MATRIX, matrix));
        effect->SetInput(0, commands, TRUE);
        effect->GetOutput(&image);
        context->BeginDraw();
        context->Clear(&white);
        context->DrawImage(image);
        CHECK(context->EndDraw());
        CHECK(output->CopyPixels(&row, 256, sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 4096; ++x)
        {
            bool inside = x % 64 + 0.5f >= 4 * scale && x % 64 + 0.5f < 20 * scale
                    && x / 64 + 0.5f >= 4 * scale && x / 64 + 0.5f < 20 * scale;
            if (inside ? pixels[x] != 0xffbfbfbf && pixels[x] != 0xffc0c0c0 : pixels[x] != 0xffffffff)
                ++differences;
        }
        printf("LAYER_COLOR_MATRIX case=%u differences=%u\n", i, differences);
        failures += differences;
        image->Release(); image = NULL;
        effect->Release(); effect = NULL;
        commands->Release(); commands = NULL;
    }
    for (i = 0; i < 12; ++i)
    {
        float dpi = (i / 3) % 2 ? 144.0f : 96.0f;
        float scale = i >= 6 ? 1.0f : dpi / 96;
        float sigma = i % 3 == 0 ? 0 : i % 3 == 1 ? 0.75f : 3;
        float deviation = sigma * dpi / 96;
        int radius = (int)ceilf(3 * deviation);
        unsigned int differences = 0;
        context->SetDpi(dpi, dpi);
        context->SetUnitMode(i >= 6 ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        for (x = 0; x < 400; ++x) source[x] = 0x80800000;
        CHECK(target->CreateBitmap(size, source, 80, &bitmap_props, &bitmap));
        CHECK(context->CreateEffect(CLSID_D2D1Shadow, &effect));
        effect->SetInput(0, (ID2D1Image *)bitmap, TRUE);
        CHECK(effect->SetValue(D2D1_SHADOW_PROP_BLUR_STANDARD_DEVIATION, sigma));
        CHECK(effect->SetValue(D2D1_SHADOW_PROP_COLOR, tint));
        effect->GetOutput(&image);
        hr = context->GetImageLocalBounds(image, &bounds);
        printf("SHADOW_BOUNDS hr=%08lx rect=%g,%g,%g,%g\n", (unsigned long)hr,
                bounds.left, bounds.top, bounds.right, bounds.bottom);
        if (FAILED(hr)) ++failures;
        target->BeginDraw();
        target->Clear(&white);
        context->DrawImage(image, &offset, NULL,
                D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, D2D1_COMPOSITE_MODE_SOURCE_OVER);
        target->FillRectangle(&rect, (ID2D1Brush *)brush);
        hr = target->EndDraw(NULL, NULL);
        printf("CASE=%u end=%08lx\n", i, (unsigned long)hr);
        if (FAILED(hr)) ++failures;
        CHECK(output->CopyPixels(&row, 256, sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 4096; ++x)
        {
            double ax = 0, ay = 0, total = 0;
            double px = x % 64 + 0.5, py = x / 64 + 0.5;
            for (int k = -radius; k <= radius; ++k)
            {
                double weight = deviation ? exp(-0.5 * k * k / (deviation * deviation)) : 1;
                if (px + k >= 12 * scale && px + k < 32 * scale) ax += weight;
                if (py + k >= 12 * scale && py + k < 32 * scale) ay += weight;
                total += weight;
            }
            double alpha = (128.0 / 255) * 0.5 * ax * ay / (total * total);
            bool following = px >= 40 * scale && px < 42 * scale && py < 2 * scale;
            unsigned int expected[4] = {255, (unsigned int)lround(255 * (1 - alpha * 0.5)),
                    (unsigned int)lround(255 * (1 - alpha * 0.75)), 255};
            if (following) expected[0] = expected[1] = expected[2] = 0;
            bool wrong = false;
            for (unsigned int c = 0; c < 4; ++c)
                if (abs((int)((pixels[x] >> (8 * c)) & 255) - (int)expected[c]) > 1) wrong = true;
            if (wrong && differences++ < 5)
                printf("MISMATCH x=%u y=%u value=%08lx expected=%02x%02x%02x%02x\n", x % 64, x / 64,
                        pixels[x], expected[3], expected[2], expected[1], expected[0]);
        }
        printf("SHADOW_ORACLE case=%u differences=%u\n", i, differences);
        failures += differences;
        image->Release(); image = NULL;
        effect->Release(); effect = NULL;
        bitmap->Release(); bitmap = NULL;
    }
    result = failures ? 1 : 0;
done:
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (image) image->Release();
    if (effect) effect->Release();
    if (bitmap) bitmap->Release();
    if (brush) brush->Release();
    if (context) context->Release();
    if (target) target->Release();
    if (factory) factory->Release();
    if (output) output->Release();
    if (imaging) imaging->Release();
    CoUninitialize();
    printf("RESULT=%s\n", result ? "FAIL" : "PASS");
    return result;
}
