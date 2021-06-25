#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

#if defined(POLYHOOK2_OS_WINDOWS)

void Polyhook2DebugBreak()
{
    __debugbreak();
}

#elif defined(POLYHOOK2_OS_LINUX)

void Polyhook2DebugBreak()
{
#if defined(__GNUC__)
    __asm__("BKPT 0");
#else
    __BKPT(0)
#endif
}

#elif defined(POLYHOOK2_OS_APPLE)

void Polyhook2DebugBreak()
{
#if defined(__GNUC__)
    __asm__("BKPT 0");
#else
    __BKPT(0)
#endif
}

#endif