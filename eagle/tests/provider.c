#define COBJMACROS
#define INITGUID
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <activation.h>
#include <dwrite.h>
#include <stdio.h>

int main(void)
{
    HSTRING name;
    IActivationFactory *activation;
    IDWriteFactory *factory;
    IDWriteFontCollection *collection;
    IDWriteFontFamily *family;
    IDWriteFont *font;
    IDWriteFontFace *face;
    IDWriteGlyphRunAnalysis *analysis;
    UINT32 codepoint = 'A';
    UINT16 glyph;
    FLOAT advance = 20;
    DWRITE_GLYPH_OFFSET offset = {0};
    DWRITE_GLYPH_RUN run = {0};
    RECT bounds;
    BYTE bitmap;
    HRESULT result;
    RoInitialize(RO_INIT_MULTITHREADED);
    WindowsCreateString(L"Windows.Eagle.Nonexistent", 25, &name);
    result = RoGetActivationFactory(name, &IID_IActivationFactory, (void **)&activation);
    WindowsDeleteString(name);
    if (result != REGDB_E_CLASSNOTREG) return 1;
    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory))) return 2;
    if (FAILED(IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE))) return 3;
    if (!IDWriteFontCollection_GetFontFamilyCount(collection)) return 4;
    if (FAILED(IDWriteFontCollection_GetFontFamily(collection, 0, &family))) return 5;
    if (FAILED(IDWriteFontFamily_GetFirstMatchingFont(family, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, &font))) return 6;
    if (FAILED(IDWriteFont_CreateFontFace(font, &face))) return 7;
    if (FAILED(IDWriteFontFace_GetGlyphIndices(face, &codepoint, 1, &glyph))) return 8;
    run.fontFace = face; run.fontEmSize = 24; run.glyphCount = 1; run.glyphIndices = &glyph; run.glyphAdvances = &advance; run.glyphOffsets = &offset;
    if (FAILED(IDWriteFactory_CreateGlyphRunAnalysis(factory, &run, 1, NULL, DWRITE_RENDERING_MODE_NATURAL, DWRITE_MEASURING_MODE_NATURAL, 0, 0, &analysis))) return 9;
    if (FAILED(IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(analysis, DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds))) return 10;
    result = IDWriteGlyphRunAnalysis_CreateAlphaTexture(analysis, DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds, &bitmap, 1);
    IDWriteGlyphRunAnalysis_Release(analysis); IDWriteFontFace_Release(face); IDWriteFont_Release(font);
    IDWriteFontFamily_Release(family); IDWriteFontCollection_Release(collection); IDWriteFactory_Release(factory);
    RoUninitialize();
    return result == E_NOT_SUFFICIENT_BUFFER ? 0 : 11;
}
