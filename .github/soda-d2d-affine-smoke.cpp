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
    ID2D1CommandList *commands = NULL;
    ID2D1Image *saved = NULL, *image = NULL;
    ID2D1Effect *effect = NULL;
    D2D1_RENDER_TARGET_PROPERTIES props = {};
    D2D1_BITMAP_PROPERTIES bitmap_props = {{DXGI_FORMAT_B8G8R8A8_UNORM,
            D2D1_ALPHA_MODE_PREMULTIPLIED}, 96, 96};
    D2D1_SIZE_U size = {8, 4};
    D2D1_COLOR_F white = {1, 1, 1, 1};
    const D2D1_MATRIX_3X2_F matrices[] = {
        {1, 0, 0, 1, 6, 8}, {2, 0, 0, 3, 6, 8}, {0, 1, -1, 0, 16, 8}, {-1, 0, 0, 1, 16, 8}};
    const D2D1_RECT_F expected[] = {{6, 8, 14, 12}, {6, 8, 22, 20}, {12, 8, 16, 16}, {8, 8, 16, 12}};
    WICRect row = {0, 0, 32, 32};
    DWORD source[32], pixels[1024];
    unsigned int i, x, failures = 0;
    HRESULT hr, end_hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory, (void **)&imaging));
    CHECK(imaging->CreateBitmap(32, 32, GUID_WICPixelFormat32bppPBGRA, WICBitmapCacheOnLoad, &output));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, IID_ID2D1Factory, NULL, (void **)&factory));
    CHECK(factory->CreateWicBitmapRenderTarget(output, &props, &target));
    CHECK(target->QueryInterface(IID_ID2D1DeviceContext, (void **)&context));
    for (x = 0; x < 32; ++x) source[x] = 0xffff0000;
    CHECK(target->CreateBitmap(size, source, 32, &bitmap_props, &bitmap));
    for (i = 0; i < 48; ++i)
    {
        D2D1_RECT_F bounds = {};
        const D2D1_RECT_F *rect = &expected[i % 4];
        D2D1_RECT_F draw_rect = *rect, clip = {7, 9, 13, 11};
        D2D1_POINT_2F offset = {3, 4};
        D2D1_MATRIX_3X2_F transform = {1, 0, 0, 1, 0, 0}, restored;
        unsigned int differences = 0;
        float dpi = i >= 40 ? 144.0f : 96.0f;
        context->SetDpi(dpi, dpi);
        CHECK(context->CreateEffect(CLSID_D2D12DAffineTransform, &effect));
        CHECK(effect->SetValue(D2D1_2DAFFINETRANSFORM_PROP_TRANSFORM_MATRIX, matrices[i % 4]));
        CHECK(effect->SetValue(D2D1_2DAFFINETRANSFORM_PROP_INTERPOLATION_MODE,
                i >= 8 && i < 24 ? D2D1_2DAFFINETRANSFORM_INTERPOLATION_MODE_LINEAR
                : D2D1_2DAFFINETRANSFORM_INTERPOLATION_MODE_NEAREST_NEIGHBOR));
        CHECK(effect->SetValue(D2D1_2DAFFINETRANSFORM_PROP_BORDER_MODE,
                i >= 16 ? D2D1_BORDER_MODE_HARD : D2D1_BORDER_MODE_SOFT));
        if (i % 8 >= 4)
        {
            context->GetTarget(&saved);
            CHECK(context->CreateCommandList(&commands));
            context->SetTarget(commands);
            context->BeginDraw();
            target->DrawBitmap(bitmap, NULL, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR, NULL);
            CHECK(context->EndDraw());
            CHECK(commands->Close());
            context->SetTarget(saved);
            saved->Release(); saved = NULL;
            effect->SetInput(0, commands);
        }
        else effect->SetInput(0, (ID2D1Image *)bitmap);
        if (i >= 32 && i < 40)
        {
            ID2D1Image *input, *shadow_image;
            ID2D1Effect *shadow;
            D2D1_VECTOR_4F tint = {1, 0, 0, 1};
            CHECK(context->CreateEffect(CLSID_D2D1Shadow, &shadow));
            effect->GetInput(0, &input);
            shadow->SetInput(0, input);
            input->Release();
            hr = shadow->SetValue(D2D1_SHADOW_PROP_BLUR_STANDARD_DEVIATION, 0.0f);
            if (SUCCEEDED(hr)) hr = shadow->SetValue(D2D1_SHADOW_PROP_COLOR, tint);
            if (FAILED(hr)) {shadow->Release(); goto done;}
            shadow->GetOutput(&shadow_image);
            effect->SetInput(0, shadow_image);
            shadow_image->Release();
            shadow->Release();
        }
        effect->GetOutput(&image);
        hr = context->GetImageLocalBounds(image, &bounds);
        printf("BOUNDS case=%u hr=%08lx rect=%g,%g,%g,%g\n", i, (unsigned long)hr,
                bounds.left, bounds.top, bounds.right, bounds.bottom);
        if (FAILED(hr) || fabsf(bounds.left - rect->left) > 0.01f || fabsf(bounds.top - rect->top) > 0.01f
                || fabsf(bounds.right - rect->right) > 0.01f || fabsf(bounds.bottom - rect->bottom) > 0.01f)
            ++failures;
        context->BeginDraw();
        context->Clear(&white);
        if (i >= 24 && i < 32)
        {
            transform._31 = 1;
            transform._32 = 2;
            context->SetTransform(transform);
            context->DrawImage(image, &offset, &clip);
            draw_rect.left = fmaxf(rect->left, clip.left) - 3;
            draw_rect.top = fmaxf(rect->top, clip.top) - 3;
            draw_rect.right = fminf(rect->right, clip.right) - 3;
            draw_rect.bottom = fminf(rect->bottom, clip.bottom) - 3;
        }
        else context->DrawImage(image);
        context->GetTransform(&restored);
        if (memcmp(&transform, &restored, sizeof(transform))) ++failures;
        transform._31 = transform._32 = 0;
        context->SetTransform(transform);
        end_hr = context->EndDraw();
        if (FAILED(end_hr)) ++failures;
        CHECK(output->CopyPixels(&row, 128, sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 1024; ++x)
        {
            float px = (x % 32 + 0.5f) * 96 / dpi, py = (x / 32 + 0.5f) * 96 / dpi;
            DWORD color = px >= draw_rect.left && px < draw_rect.right && py >= draw_rect.top && py < draw_rect.bottom
                    ? 0xffff0000 : 0xffffffff;
            if (color == 0xffff0000 && i >= 8 && i < 16 && i % 4 == 1)
            {
                float sx = (px - 6) / 2, sy = (py - 8) / 3;
                float ax = fminf(1, fminf(sx + 0.5f, 8.5f - sx));
                float ay = fminf(1, fminf(sy + 0.5f, 4.5f - sy));
                DWORD channel = lroundf(255 * (1 - ax * ay));
                color |= channel | channel << 8;
            }
            bool wrong = false;
            for (unsigned int c = 0; c < 4; ++c)
                if (abs((int)((pixels[x] >> (8 * c)) & 255) - (int)((color >> (8 * c)) & 255)) > 1)
                    wrong = true;
            if (wrong) ++differences;
        }
        printf("AFFINE case=%u end=%08lx differences=%u\n", i, (unsigned long)end_hr, differences);
        failures += differences;
        image->Release(); image = NULL;
        effect->Release(); effect = NULL;
        if (commands) {commands->Release(); commands = NULL;}
    }
    result = failures ? 1 : 0;
done:
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (image) image->Release();
    if (effect) effect->Release();
    if (bitmap) bitmap->Release();
    if (context) context->Release();
    if (target) target->Release();
    if (factory) factory->Release();
    if (output) output->Release();
    if (imaging) imaging->Release();
    CoUninitialize();
    printf("RESULT=%s failures=%u\n", result ? "FAIL" : "PASS", failures);
    return result;
}
