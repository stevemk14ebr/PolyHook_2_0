#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

#include <memoryapi.h>

EffectTracker ripEffects;

unsigned char cmpQwordImm[] = {
    0x48, 0x81, 0x3D, 0xF5, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12, // cmp qword ptr ds:[rip - 11], 0x12345678
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,                         // mov rax, 0x1337
    0xC3                                                              // ret
};


unsigned char cmpDwordImm[] = {
    0x81, 0x05, 0xF6, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12, // add dword ptr ds:[rip - 10], 0x12345678
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,                   // mov rax, 0x1337
    0xC3                                                        // ret
};

unsigned char cmpWordImm[] = {
    0x66, 0x81, 0x3D, 0xF7, 0xFF, 0xFF, 0xFF, 0x34, 0x12, // cmp word ptr ds:[rip - 9], 0x1234
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,             // mov rax, 0x1337
    0xC3                                                  // ret
};

unsigned char cmpByteImm[] = {
    0x80, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF, 0x12, // cmp byte ptr ds:[rip - 7], 0x12
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, // mov rax, 0x1337
    0xC3                                      // ret
};

unsigned char cmpQwordRegR10[] = {
    0x4C, 0x39, 0x15, 0xF9, 0xFF, 0xFF, 0xFF, // cmp qword ptr ds:[rip - 7], r10
    0xB8, 0x37, 0x13, 0x00, 0x00,             // mov eax, 0x1337
    0xC3                                      // ret
};

unsigned char cmpRegADword[] = {
    0x3B, 0x05, 0xFA, 0xFF, 0xFF, 0xFF, // cmp eax, dword ptr ds:[rip - 6]
    0x90, 0x90, 0x90, 0x90,             // nop x4
    0xC3                                // ret
};

unsigned char cmpWordRegB[] = {
    0x66, 0x39, 0x1D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp word ptr ds:[rip - 7], bx
    0x90, 0x90, 0x90, 0x90,                   // nop x4
    0xC3                                      // ret
};

unsigned char cmpR15bByte[] = {
    0x44, 0x3A, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp r15b, byte ptr ds:[rip - 7]
    0x90, 0x90, 0x90, 0x90,                   // nop x4
    0xC3                                      // ret
};

// TODO: Translation + INPLACE scheme

uint64_t oCmpQwordImm = NULL;

uint64_t hookCmpQwordImm() {
    PLH::StackCanary canary;
    ripEffects.PeakEffect().trigger();

    printf("Hooked %s\n", __func__);

    return PLH::FnCast(oCmpQwordImm, &hookCmpQwordImm)();
}

uint64_t oCmpQwordReg = NULL;

uint64_t hookCmpQwordReg() {
    PLH::StackCanary canary;
    ripEffects.PeakEffect().trigger();

    printf("Hooked %s\n", __func__);

    return PLH::FnCast(oCmpQwordReg, &hookCmpQwordReg)();
}

TEST_CASE("Testing Detours with Translations", "[Translation][ADetour]") {
    // Immediate

    SECTION("cmp qword & imm") {
        PLH::StackCanary canary;

        DWORD flOldProtect;
        VirtualProtect((void*) cmpQwordImm, (SIZE_T) sizeof(cmpQwordImm), PAGE_EXECUTE_READWRITE, &flOldProtect);

        PLH::x64Detour detour((uint64_t) cmpQwordImm, (uint64_t) hookCmpQwordImm, &oCmpQwordImm);

        REQUIRE(detour.hook());

        ripEffects.PushEffect();

        const auto result = PLH::FnCast(cmpQwordImm, hookCmpQwordImm)();

        REQUIRE(ripEffects.PopEffect().didExecute());
        REQUIRE(result == 0x1337);

        REQUIRE(detour.unHook());
    }

    SECTION("cmp dword & imm") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpDwordImm, (uint64_t) hookCmpQwordImm, &oCmpQwordImm);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }


    SECTION("cmp word & imm") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpWordImm, (uint64_t) hookCmpQwordImm, &oCmpQwordImm);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }

    SECTION("cmp byte & imm") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpByteImm, (uint64_t) hookCmpQwordImm, &oCmpQwordImm);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }

        // Registers

    SECTION("cmp qword & reg") {
        PLH::StackCanary canary;

        DWORD flOldProtect;
        VirtualProtect((void*) cmpQwordRegR10, (SIZE_T) sizeof(cmpQwordRegR10), PAGE_EXECUTE_READWRITE, &flOldProtect);

        PLH::x64Detour detour((uint64_t) cmpQwordRegR10, (uint64_t) hookCmpQwordReg, &oCmpQwordReg);

        REQUIRE(detour.hook());

        ripEffects.PushEffect();

        const auto result = PLH::FnCast(cmpQwordRegR10, hookCmpQwordReg)();

        REQUIRE(ripEffects.PopEffect().didExecute());
        REQUIRE(result == 0x1337);

        REQUIRE(detour.unHook());
    }

        // Subsequent hooks don't test trampoline calls

    SECTION("cmp dword & reg") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpRegADword, (uint64_t) hookCmpQwordReg, &oCmpQwordReg);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }

    SECTION("cmp word & reg") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpWordRegB, (uint64_t) hookCmpQwordReg, &oCmpQwordReg);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }

    SECTION("cmp byte & reg") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) cmpR15bByte, (uint64_t) hookCmpQwordReg, &oCmpQwordReg);

        REQUIRE(detour.hook());
        REQUIRE(detour.unHook());
    }

}
