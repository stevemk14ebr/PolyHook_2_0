#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

#if defined(POLYHOOK2_OS_WINDOWS)

void PolyHook2DebugBreak()
{
    __debugbreak();
}

void* PolyHook2Alloca(size_t size)
{
    return _alloca(size);
}

#elif defined(POLYHOOK2_OS_LINUX)

void PolyHook2DebugBreak()
{
#if defined(__GNUC__)
    __asm__("BKPT 0");
#else
    __BKPT(0)
#endif
}

void* PolyHook2Alloca(size_t size)
{
    return alloca(size);
}

#elif defined(POLYHOOK2_OS_APPLE)

void PolyHook2DebugBreak()
{
#if defined(__GNUC__)
    __asm__("BKPT 0");
#else
    __BKPT(0)
#endif
}

void* PolyHook2Alloca(size_t size)
{
    return alloca(size);
}

#endif