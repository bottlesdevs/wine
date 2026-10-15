#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    FILE *file;
    if (argc != 3 || strcmp(argv[1], "eagle-fixture://signin")) return 1;
    if (!(file = fopen(argv[2], "wb"))) return 2;
    fputs("fixture URI acknowledged\n", file);
    return fclose(file) ? 3 : 0;
}
