#pragma once

#include <cstdint>

// clang-format off
/**
 * This macro is used to define a hooked function that needs to proxy calls to the original one.
 * The main challenge with such a macro is that it needs to perfectly mirror original function signature,
 *   especially the noexcept attribute.
 * This is accomplished by using inner noexcept, which
 *   tests whether calling the original function with those arguments would be noexcept
 * and outer noexcept, which
 *   uses the result of that test to set the noexcept specification on the lambda.
 * In simple terms, this construct says:
 * "This lambda is noexcept if and only if calling the original function with the same arguments would be noexcept."
 * This is a compile-time mechanism that perfectly mirrors the exception specification of the original function.
 *
 * Note that this is not supported by GCC, since generic lambdas cannot be assigned to function pointers in GCC.
 * Clang allows generic lambdas to decay to function pointers if the instantiated signature matches.
 * This is a known divergence from the C++ standard.
 */
#define PLH_TEST_CALLBACK(FUNC, HOOK, TRMP, ...) \
    uint64_t TRMP = 0; \
    decltype(&FUNC) HOOK = []<typename... Args>(Args... $args) \
        noexcept(noexcept(std::declval<decltype(&FUNC)>()(std::declval<Args>()...))) -> auto { \
        PLH::StackCanary canary; \
        PLH_STOP_OPTIMIZATIONS(); \
		effects.PeakEffect().trigger(); \
        __VA_ARGS__ \
        return PLH::FnCast(TRMP, &FUNC)($args...); \
    }
// clang-format on

/**
 * Most test hooks follow the same convention,
 * where hooked functions and trampoline variables derive their name from the original function.
 * Hence, it makes sense to create a corresponding macro utility
 */
#define PLH_TEST_DETOUR_CALLBACK(FUNC, ...) PLH_TEST_CALLBACK(FUNC, FUNC##_hooked, FUNC##_trmp, __VA_ARGS__)
#define PLH_TEST_DETOUR(FUNC) detour((uint64_t)&FUNC, (uint64_t)FUNC##_hooked, &FUNC##_trmp);

/**
 * These tests can spontaneously fail if the compiler decides to optimize away
 * the handler or inline the function. PLH_NOINLINE attempts to fix the latter, the former
 * is out of our control but typically returning volatile things, volatile locals, and a
 * printf inside the body can mitigate this significantly. Do serious checking in Debug
 * or ReleaseWithDebInfo mode (ReleaseWithDebInfo optimizes _slightly_ less).
 */
#define PLH_STOP_OPTIMIZATIONS()                                                                                       \
	volatile int i = 0;                                                                                                \
	PH_UNUSED(i)

namespace PLH::test {

void registerTestLogger();

}
