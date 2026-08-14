#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void write_marker(void)
{
    const char *marker = getenv("MCSODA_D3DMETAL_SMOKE_MARKER");
    FILE *file;

    if (!marker) return;
    file = fopen(marker, "a");
    if (!file) return;
    fputs("loaded\n", file);
    fclose(file);
}

__attribute__((constructor)) static void library_loaded(void)
{
    write_marker();
}

bool supports_non_native_code_regions(void)
{
    return true;
}

void register_non_native_code_region(void *start, void *end)
{
    write_marker();
}
