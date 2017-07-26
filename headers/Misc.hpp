//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MISC_HPP
#define POLYHOOK_2_0_MISC_HPP

#include <stdexcept>
#include <cassert>

namespace PLH {
enum class Platform
{
    WIN,
    UNIX
};

class NotImplementedException : public std::logic_error
{
public:
    NotImplementedException() : std::logic_error("Function not implemented") {

    }
};

class ValueNotSetException : public std::logic_error
{
public:
    ValueNotSetException() : std::logic_error("Value not set in optional object") {

    }
};

class AllocationFailure : public std::logic_error
{
public:
    AllocationFailure() : std::logic_error("Unable to allocate memory within range") {

    }
};

//http://stackoverflow.com/questions/4840410/how-to-align-a-pointer-in-c
static inline char* AlignUpwards(const char* stack, size_t align) {
    assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
    assert(stack != 0);

    auto addr = reinterpret_cast<uintptr_t>(stack);
    if (addr % align != 0)
        addr += align - addr % align;
    assert(addr >= reinterpret_cast<uintptr_t>(stack));
    return reinterpret_cast<char*>(addr);
}

static inline char* AlignDownwards(const char* stack, size_t align) {
    assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
    assert(stack != 0);

    auto addr = reinterpret_cast<uintptr_t>(stack);
    addr -= addr % align;
    assert(addr <= reinterpret_cast<uintptr_t>(stack));
    return reinterpret_cast<char*>(addr);
}

template <typename T, T> struct proxy;

template <typename T, typename R, typename... Args, R (T::*mf)(Args...)>
struct proxy<R (T::*)(Args...), mf>
{
    typedef R (*TCallback)(Args...);
    __attribute_noinline__ static R call(T* obj, Args&&... args)
    {
        return (*obj.*mf)(std::forward<Args>(args)...);
    }
};
}
#endif //POLYHOOK_2_0_MISC_HPP
