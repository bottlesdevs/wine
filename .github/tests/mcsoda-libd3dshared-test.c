#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    bool (*supports_non_native_code_regions)(void);
    void (*register_non_native_code_region)(void *, void *);
    void *library;

    if (argc != 2) return 1;
    library = dlopen(argv[1], RTLD_LOCAL | RTLD_NOW);
    if (!library)
    {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    supports_non_native_code_regions = dlsym(library, "supports_non_native_code_regions");
    register_non_native_code_region = dlsym(library, "register_non_native_code_region");
    if (!supports_non_native_code_regions || !register_non_native_code_region) return 3;
    if (!supports_non_native_code_regions()) return 4;

    puts("McSoda external libd3dshared test");
    return 0;
}
