#include <Catch.hpp>

#include "polyhook2/Detour/ILCallback.hpp"

#pragma warning( disable : 4244)

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

EffectTracker effectsNTD64;

#include "polyhook2/Detour/x64Detour.hpp"

NOINLINE void hookMeInt(int a) {
    PLH::StackCanary canary;
    volatile int var = 1;
    int var2 = var + a;

#ifdef _MSC_VER
    auto retAddress = (uint64_t) _ReturnAddress();
#elif __GNUC__
    auto retAddress = (uint64_t)__builtin_return_address(0);
#else
#error "Please implement this for your compiler."
#endif

    printf("%d %d %I64X\n", var, var2, retAddress);
}

NOINLINE void hookMeFloat(float a) {
    PLH::StackCanary canary;
    float ans = 1.0f;
    ans += a;
    printf("%f %f\n", ans, a);
}

NOINLINE void hookMeIntFloatDouble(int a, float b, double c) {
    PLH::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void
myCallback(const PLH::ILCallback::Parameters* p, const uint8_t count, const PLH::ILCallback::ReturnValue* retVal) {
    PH_UNUSED(retVal);
    PLH::StackCanary canary;

    printf("Argument Count: %d\n", count);
    for (int i = 0; i < count; i++) {
        printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, p->getArg<int>(i), p->getArg<float>(i),
               p->getArg<double>(i));

        // one of the args must be pretty l33t
        auto fArg = p->getArg<float>(i);
        auto dArg = p->getArg<double>(i);
        if (p->getArg<int>(i) == 1337 || (fArg > 1336.0f && fArg < 1338.0f) || (dArg > 1336.0 && dArg < 1338.0)) {
            effectsNTD64.PeakEffect().trigger();
        }
    }
}

TEST_CASE("Minimal ILCallback", "[AsmJit][ILCallback]") {
    PLH::ILCallback callback;
    SECTION("Integer argument") {
        PLH::StackCanary canary;
        asmjit::FuncSignatureT<void, int> sig;
        sig.setCallConvId(asmjit::CallConvId::kX64Windows);
        uint64_t JIT = callback.getJitFunc(sig, asmjit::Arch::kHost, &myCallback);
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &hookMeInt, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        hookMeInt(1337);
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Floating argument") {
        PLH::StackCanary canary;
        uint64_t JIT = callback.getJitFunc("void", {"float"}, asmjit::Arch::kHost, &myCallback);
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &hookMeFloat, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        hookMeFloat(1337.1337f);
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Int, float, double arguments, string parsing types") {
        PLH::StackCanary canary;
        uint64_t JIT = callback.getJitFunc("void", {"int", "float", "double"}, asmjit::Arch::kHost, &myCallback);
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &hookMeIntFloatDouble, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        hookMeIntFloatDouble(1337, 1337.1337f, 1337.1337);
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }
}


NOINLINE void rw(int a, float b, double c, int type) {
    PH_UNUSED(type);
    PLH::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.PeakEffect().trigger();
    }
    printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE float rw_float(int a, float b, double c, int type) {
    PH_UNUSED(type);
    PLH::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.PeakEffect().trigger();
    }
    printf("%d %f %f %f\n", a, b, c, ans);
    return ans;
}

NOINLINE double rw_double(int a, float b, double c, int type) {
    PH_UNUSED(type);
    PLH::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.PeakEffect().trigger();
    }
    printf("%d %f %f %f\n", a, b, c, ans);
    return c;
}

// TODO: Delete unused function?
NOINLINE int rw_int(int a, float b, double c, int type) {
    PH_UNUSED(type);
    PLH::StackCanary canary;
    volatile float ans = 0.0f;
    ans += (float) a;
    ans += (float) c;
    ans += b;
    if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
        effectsNTD64.PeakEffect().trigger();
    }
    printf("%d %f %f %f\n", a, b, c, ans);
    return a;
}

NOINLINE void mySecondCallback(
    const PLH::ILCallback::Parameters* p,
    const uint8_t count,
    const PLH::ILCallback::ReturnValue* retVal
) {
    PLH::StackCanary canary;
    printf("Argument Count: %d\n", count);
    for (int i = 0; i < count; i++) {
        printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, p->getArg<int>(i), p->getArg<float>(i),
               p->getArg<double>(i));

        // re-write to 5 iff it's l33t
        auto fArg = p->getArg<float>(i);
        auto dArg = p->getArg<double>(i);
        if (p->getArg<int>(i) == 1337) {
            p->setArg<int>(i, 5);
        } else if ((fArg > 1336.0f && fArg < 1338.0f)) {
            p->setArg<float>(i, 5.0f);
        } else if (dArg > 1336.0 && dArg < 1338.0) {
            p->setArg<double>(i, 5.0);
        }
    }

    // little hack, use 4th param to test different return types
    switch (p->getArg<int>(3)) {
        case 0: *(int*) retVal->getRetPtr() = 1337;
            break;
        case 1: *(float*) retVal->getRetPtr() = 1337.0f;
            break;
        case 2: *(double*) retVal->getRetPtr() = 1337.0;
            break;
        default: printf("Unknown Mode, NOT modifying ret val!\n");
    }
}

TEST_CASE("ILCallback Argument re-writing", "[ILCallback]") {
    PLH::ILCallback callback;

    SECTION("Int, float, double arguments host") {
        PLH::StackCanary canary;
        uint64_t JIT = callback.getJitFunc(
            "void", {"int", "float", "double", "int"}, asmjit::Arch::kHost, &mySecondCallback
        );
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &rw, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        rw(1337, 1337.1337f, 1337.1337, 0);
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Int, float, double arguments, float ret, host") {
        PLH::StackCanary canary;
        uint64_t JIT = callback.getJitFunc(
            "float", {"int", "float", "double", "int"}, asmjit::Arch::kHost, &mySecondCallback
        );
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &rw_float, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        float f = rw_float(1337, 1337.1337f, 1337.1337, 1);
        REQUIRE(f == Approx(1337.0f));
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Int, float, double arguments, double ret, host") {
        PLH::StackCanary canary;
        uint64_t JIT = callback.getJitFunc(
            "double", {"int", "float", "double", "int"}, asmjit::Arch::kHost, &mySecondCallback
        );
        REQUIRE(JIT != 0);

        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour detour((uint64_t) &rw_double, (uint64_t) JIT, callback.getTrampolineHolder());
        REQUIRE(detour.hook() == true);

        effectsNTD64.PushEffect();
        double d = rw_double(1337, 1337.1337f, 1337.1337, 2);
        REQUIRE(d == Approx(1337.0));
        REQUIRE(effectsNTD64.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }
}
