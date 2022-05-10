#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

EffectTracker schemeEffects;

TEST_CASE("Testing detour schemes", "[DetourScheme][ADetour]") {
    typedef uint64_t (* IntFn)();

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
            exit(1);
        }

        return fn;
    };

    SECTION("Validate valloc2 scheme in function with translation and back-references") {
        PLH::StackCanary canary;

        auto valloc_function = make_func([](asmjit::x86::Assembler& a) {
            auto SetRax = a.newLabel();
            auto Exit = a.newLabel();

            a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rip, -11), 0x12345678);

            a.bind(SetRax);
            a.cmp(asmjit::x86::rax, 0x1337);
            a.je(Exit);
            a.mov(asmjit::x86::rax, 0x1337);
            a.jmp(SetRax);

            a.bind(Exit);
            a.ret();
        });

        static uint64_t tramp_valloc_function;
        IntFn hook_valloc_function = []() {
            PLH::StackCanary canary;
            schemeEffects.PeakEffect().trigger();
            printf("hook_valloc_function called");
            return ((IntFn) (tramp_valloc_function))();
        };

        PLH::x64Detour detour((uint64_t) valloc_function, (uint64_t) hook_valloc_function, &tramp_valloc_function);
        detour.setDetourScheme(PLH::x64Detour::detour_scheme_t::VALLOC2);
        REQUIRE(detour.hook());
        schemeEffects.PushEffect();
        REQUIRE(valloc_function() == 0x1337);
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Validate in-place scheme in large function") {
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
        REQUIRE(detour.hook());
        schemeEffects.PushEffect();
        large_function();
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Validate in-place scheme in medium function") {
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
        REQUIRE(detour2.hook());
        schemeEffects.PushEffect();
        medium_function();
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour2.unHook());
    }

    SECTION("Validate in-place scheme in function with translation") {
        PLH::StackCanary canary;

        auto rip_function = make_func([](asmjit::x86::Assembler& a) {
            a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rip, -11), 0x12345678);
            a.mov(asmjit::x86::rax, 0x1337);
            a.ret();
        });

        static uint64_t tramp_rip_function;
        IntFn hook_rip_function = []() {
            PLH::StackCanary canary;
            schemeEffects.PeakEffect().trigger();
            printf("hook_rip_function called");
            return ((IntFn) (tramp_rip_function))();
        };

        PLH::x64Detour detour((uint64_t) rip_function, (uint64_t) hook_rip_function, &tramp_rip_function);
        detour.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE_SHORT);
        REQUIRE(detour.hook());
        schemeEffects.PushEffect();
        REQUIRE(rip_function() == 0x1337);
        REQUIRE(schemeEffects.PopEffect().didExecute());
        REQUIRE(detour.unHook());
    }

    SECTION("Validate code-cave scheme in small function") {
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

        // TODO: Polyhook is not guaranteed to find a cave, hence this test will often fail.
        // We need to find a way to deliberately reserve code cave.

        // PLH::x64Detour detour2((uint64_t) small_function, (uint64_t) hook_small_function, &tramp_small_function);
        // detour2.setDetourScheme(PLH::x64Detour::detour_scheme_t::CODE_CAVE);
        // REQUIRE(detour2.hook());
        // schemeEffects.PushEffect();
        // small_function();
        // REQUIRE(schemeEffects.PopEffect().didExecute());
        // REQUIRE(detour2.unHook());
    }
}
