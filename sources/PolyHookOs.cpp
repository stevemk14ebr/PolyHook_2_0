#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

#if defined(POLYHOOK2_OS_WINDOWS)

void PolyHook2DebugBreak()
{
    __debugbreak();
}

#elif defined(POLYHOOK2_OS_LINUX)

void PolyHook2DebugBreak()
{
    __asm__("int3");
}

#elif defined(POLYHOOK2_OS_APPLE)

void PolyHook2DebugBreak()
{
    __asm__("int3");
}

#endif
