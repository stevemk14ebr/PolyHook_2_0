#include "polyhook2/PolyHookOs.hpp"

#ifdef POLYHOOK2_OS_WINDOWS

#include <debugapi.h>

void PolyHook2DebugBreak() {
    DebugBreak();
}

#else

void PolyHook2DebugBreak() {
    __asm__("int3");
}

#endif
