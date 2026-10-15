__declspec(dllimport) int EagleDependencyValue(void);
__declspec(dllexport) int EagleParentValue(void) { return EagleDependencyValue(); }
