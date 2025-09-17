#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

#ifdef POLYHOOK2_OS_WINDOWS

void PolyHook2DebugBreak() {
    DebugBreak();
}

#else

void PolyHook2DebugBreak() {
    __asm__("int3");
}

#endif
