#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/ZydisDisassembler.hpp"

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

unsigned char cmpQwordRegR10[] = {
	0x4C, 0x39, 0x15, 0xF9, 0xFF, 0xFF, 0xFF, // cmp qword ptr ds:[rip - 7], r10
	0xB8, 0x37, 0x13, 0x00, 0x00,             // mov eax, 0x1337
	0xC3                                      // ret
};

unsigned char cmpDwordRegA[] = {
	0x39, 0x05, 0xFA, 0xFF, 0xFF, 0xFF, // cmp dword ptr ds:[rip - 6], eax
	0x90, 0x90, 0x90, 0x90,             // nop x4
	0xC3                                // ret
};

unsigned char cmpWordRegB[] = {
	0x66, 0x39, 0x1D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp word ptr ds:[rip - 7], bx
	0x90, 0x90, 0x90, 0x90,                   // nop x4
	0xC3                                      // ret
};

unsigned char cmpByteRegR8b[] = {
	0x44, 0x38, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF, // cmp byte ptr ds:[rip - 7], r15b
	0x90, 0x90, 0x90, 0x90,                   // nop x4
	0xC3                                      // ret
};

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

TEST_CASE("Testing RIP-relative detours", "[RipDetour][ADetour]") {
	PLH::ZydisDisassembler dis(PLH::Mode::x64);

	SECTION("cmp qword & reg") {
		PLH::StackCanary canary;

		DWORD flOldProtect;
		VirtualProtect((void*) cmpQwordRegR10, (SIZE_T) sizeof(cmpQwordRegR10), PAGE_EXECUTE_READWRITE, &flOldProtect);

		PLH::x64Detour detour((char*) cmpQwordRegR10, (char*) hookCmpQwordReg, &oCmpQwordReg, dis);

		REQUIRE(detour.hook() == true);

		ripEffects.PushEffect();

		const auto result = PLH::FnCast(cmpQwordRegR10, hookCmpQwordReg)();

		REQUIRE(ripEffects.PopEffect().didExecute());
		REQUIRE(result == 0x1337);

		REQUIRE(detour.unHook() == true);
	}

		// Subsequent hooks don't test trampoline calls

	SECTION("cmp dword & reg") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*) cmpDwordRegA, (char*) hookCmpQwordImm, &oCmpQwordImm, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("cmp word & reg") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*) cmpWordRegB, (char*) hookCmpQwordImm, &oCmpQwordImm, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("cmp byte & reg") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*) cmpByteRegR8b, (char*) hookCmpQwordImm, &oCmpQwordImm, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

/*	SECTION("cmp qword & imm") {
		PLH::StackCanary canary;

		DWORD flOldProtect;
		VirtualProtect((void*) cmpQwordImm, (SIZE_T) sizeof(cmpQwordImm), PAGE_EXECUTE_READWRITE, &flOldProtect);

		PLH::x64Detour detour((char*) cmpQwordImm, (char*) hookCmpQwordImm, &oCmpQwordImm, dis);

		REQUIRE(detour.hook() == true);

		ripEffects.PushEffect();

		const auto result = PLH::FnCast(cmpQwordImm, hookCmpQwordImm)();

		REQUIRE(ripEffects.PopEffect().didExecute());
		REQUIRE(result == 0x1337);

		REQUIRE(detour.unHook() == true);
	}*/


}
