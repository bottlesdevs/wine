#include <windows.h>
#include <d2d1_1.h>
#include <d2d1effects.h>
#include <dwrite.h>
#include <wincodec.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *output = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1DeviceContext *context = NULL;
    ID2D1SolidColorBrush *brush = NULL;
    D2D1_RENDER_TARGET_PROPERTIES props = {};
    D2D1_COLOR_F black = {0, 0, 0, 1};
    ID2D1Effect *effect = NULL;
    ID2D1Image *image = NULL;
    ID2D1CommandList *commands = NULL;
    ID2D1Image *saved = NULL;
    D2D1_RECT_F bounds = {};
    unsigned int x, drawn = 0, failures = 0;
    DWORD pixels[4096];
    WICRect area = {0, 0, 64, 64};
    D2D1_COLOR_F white = {1, 1, 1, 1};
    IDWriteFactory *write = NULL;
    IDWriteFontCollection *fonts = NULL;
    IDWriteFontFamily *family = NULL;
    IDWriteFont *font = NULL;
    IDWriteFontFace *face = NULL;
    IDWriteGlyphRunAnalysis *analysis = NULL;
    UINT32 codes[] = {'A', 'g'};
    UINT16 indices[2];
    FLOAT advances[] = {20, 20};
    DWRITE_GLYPH_RUN run = {};
    D2D1_POINT_2F baseline = {10, 32};
    DWORD reference[4096];
    float dpi = argc > 1 ? atof(argv[1]) : 96;
    D2D1_UNIT_MODE units = argc > 2 && atoi(argv[2]) ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS;
    D2D1_MATRIX_3X2_F transform = {1, 0, 0, 1, 0, 0};
    D2D1_MATRIX_3X2_F identity = {1, 0, 0, 1, 0, 0};
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
    CHECK(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown **)&write));
    CHECK(write->GetSystemFontCollection(&fonts));
    CHECK(fonts->GetFontFamily(0, &family));
    CHECK(family->GetFirstMatchingFont(DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            DWRITE_FONT_STYLE_NORMAL, &font));
    CHECK(font->CreateFontFace(&face));
    CHECK(face->GetGlyphIndices(codes, 2, indices));
    run.fontFace = face;
    run.fontEmSize = 24;
    run.glyphCount = 2;
    run.glyphIndices = indices;
    run.glyphAdvances = advances;
    {
        DWRITE_MATRIX matrix = {1, 0, 0, 1, 0, 0};
        RECT positive, negative;
        CHECK(write->CreateGlyphRunAnalysis(&run, 1, &matrix, DWRITE_RENDERING_MODE_NATURAL,
                DWRITE_MEASURING_MODE_NATURAL, 4.5f, 32, &analysis));
        CHECK(analysis->GetAlphaTextureBounds(DWRITE_TEXTURE_CLEARTYPE_3x1, &positive));
        analysis->Release(); analysis = NULL;
        CHECK(write->CreateGlyphRunAnalysis(&run, 1, &matrix, DWRITE_RENDERING_MODE_NATURAL,
                DWRITE_MEASURING_MODE_NATURAL, -1.5f, 32, &analysis));
        CHECK(analysis->GetAlphaTextureBounds(DWRITE_TEXTURE_CLEARTYPE_3x1, &negative));
        analysis->Release(); analysis = NULL;
        printf("TRANSLATION expected=6 left=%ld right=%ld\n",
                positive.left - negative.left, positive.right - negative.right);
        if (positive.left - negative.left != 6 || positive.right - negative.right != 6) ++failures;
    }
    if (argc > 3 && atoi(argv[3]))
    {
        transform._11 = 0.75f;
        transform._22 = 1.25f;
        transform._31 = -3;
        transform._32 = 2;
    }
    context->SetDpi(dpi, dpi);
    context->SetUnitMode(units);
    context->SetTransform(&transform);
    context->GetTarget(&saved);
    context->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
    context->BeginDraw();
    context->Clear(&white);
    context->DrawGlyphRun(baseline, &run, NULL, brush, DWRITE_MEASURING_MODE_NATURAL);
    CHECK(context->EndDraw());
    CHECK(output->CopyPixels(&area, 256, sizeof(reference), (BYTE *)reference));
    for (x = 0; x < 4096; ++x) if (reference[x] != 0xffffffff) ++drawn;
    if (!drawn) ++failures;
    CHECK(context->CreateCommandList(&commands));
    context->SetTarget(commands);
    context->BeginDraw();
    context->DrawGlyphRun(baseline, &run, NULL, brush, DWRITE_MEASURING_MODE_NATURAL);
    CHECK(context->EndDraw());
    CHECK(commands->Close());
    context->SetTarget(saved);
    context->SetTransform(&identity);
    CHECK(context->GetImageLocalBounds(commands, &bounds));
    printf("GLYPH_BOUNDS hr=%08lx rect=%g,%g,%g,%g\n", (unsigned long)hr,
            bounds.left, bounds.top, bounds.right, bounds.bottom);
    CHECK(context->CreateEffect(CLSID_D2D1ColorMatrix, &effect));
    effect->SetInput(0, commands, TRUE);
    effect->GetOutput(&image);
    context->BeginDraw();
    context->Clear(&white);
    context->DrawImage(image);
    CHECK(context->EndDraw());
    CHECK(output->CopyPixels(&area, 256, sizeof(pixels), (BYTE *)pixels));
    for (x = 0; x < 4096; ++x)
        if (pixels[x] != reference[x]) ++failures;
    printf("GLYPH_PIXELS differences=%u\n", failures);
    result = failures ? 1 : 0;
done:
    if (analysis) analysis->Release();
    if (face) face->Release();
    if (font) font->Release();
    if (family) family->Release();
    if (fonts) fonts->Release();
    if (write) write->Release();
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (image) image->Release();
    if (effect) effect->Release();
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
