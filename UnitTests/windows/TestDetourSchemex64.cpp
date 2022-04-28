#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

EffectTracker schemeEffects;

TEST_CASE("Testing detour schemes", "[DetourScheme][ADetour]") {
    typedef int (* IntFn)();

    asmjit::JitRuntime rt;

    auto make_func = [&](const std::function<void(asmjit::x86::Assembler&)>& builder) {
        asmjit::CodeHolder code;
        code.init(rt.environment());
        asmjit::x86::Assembler a(&code);
        builder(a);

        IntFn fn;
        auto error = rt.add(&fn, &code);

        if (error) {
            const auto message = std::string("Error generating function: ") + asmjit::DebugUtils::errorAsString(error);
            PLH::Log::log(message, PLH::ErrorLevel::SEV);
        }

        return fn;
    };

    SECTION("Validate in-place detour scheme in large function") {
        PLH::StackCanary canary;

        auto large_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.mov(asmjit::x86::rbx, 0x6543210987654321);
            a.mov(asmjit::x86::rcx, 0x1234567890ABCDEF);
            a.mov(asmjit::x86::rcx, 0xFEDCBA0987654321);
            a.ret();
        });

        static uint64_t tramp_large_function;
        IntFn hook_large_function = []() {
            PLH::StackCanary canary;
            schemeEffects.PeakEffect().trigger();
            printf("hook_large_function called");
            return ((IntFn) (tramp_large_function))();
        };

        PLH::x64Detour detour((uint64_t) large_function, (uint64_t) hook_large_function, &tramp_large_function);
        detour.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE);
        REQUIRE(detour.hook() == true);
        schemeEffects.PushEffect();
        large_function();
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Validate in-place detour scheme in medium function") {
        PLH::StackCanary canary;

        auto medium_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.mov(asmjit::x86::rcx, 0x1234567890ABCDEF);
            a.ret();
        });

        static uint64_t tramp_medium_function;
        IntFn hook_medium_function = []() {
            PLH::StackCanary canary;
            schemeEffects.PeakEffect().trigger();
            printf("hook_medium_function called");
            return ((IntFn) (tramp_medium_function))();
        };

        PLH::x64Detour detour1((uint64_t) medium_function, (uint64_t) hook_medium_function, &tramp_medium_function);
        detour1.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE);
        REQUIRE(detour1.hook() == false);

        PLH::x64Detour detour2((uint64_t) medium_function, (uint64_t) hook_medium_function, &tramp_medium_function);
        detour2.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour2.hook() == true);
        schemeEffects.PushEffect();
        medium_function();
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour2.unHook() == true);
    }

    SECTION("Validate code-cave detour scheme in small function") {
        PLH::StackCanary canary;

        auto small_function = make_func([](auto& a) {
            a.mov(asmjit::x86::rax, 0x1234567890123456);
            a.ret();
        });

        static uint64_t tramp_small_function;
        IntFn hook_small_function = []() {
            PLH::StackCanary canary;
            schemeEffects.PeakEffect().trigger();
            printf("tramp_small_function called");
            return ((IntFn) (tramp_small_function))();
        };

        PLH::x64Detour detour1((uint64_t) small_function, (uint64_t) hook_small_function, &tramp_small_function);
        detour1.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour1.hook() == false);


        // FIXME: Is not guaranteed to find a cave
        PLH::x64Detour detour2((uint64_t) small_function, (uint64_t) hook_small_function, &tramp_small_function);
        detour2.setDetourScheme(PLH::x64Detour::detour_scheme_t::CODE_CAVE);
        REQUIRE(detour2.hook() == true);
        schemeEffects.PushEffect();
        small_function();
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour2.unHook() == true);
    }
}
