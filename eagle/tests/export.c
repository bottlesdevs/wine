__declspec(dllexport) __declspec(noinline) int eagle_export_add(int value)
{
    volatile int result = value + 1;
    return result;
}
