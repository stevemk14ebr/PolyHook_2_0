//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>
#include "headers/Detour/X64Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

#include "headers/tests/TestEffectTracker.hpp"

EffectTracker effects;

NOINLINE void hookMe1() {
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
	REQUIRE(var == 2);
	REQUIRE(var2 == 40);
}
uint64_t hookMe1Tramp = NULL;

NOINLINE void h_hookMe1() {
	std::cout << "Hook 1 Called!" << std::endl;
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe1Tramp, &hookMe1)();
}

NOINLINE void hookMe2() {
	for (int i = 0; i < 10; i++) {
		printf("%d\n", i); 
	}
}
uint64_t hookMe2Tramp = NULL;

NOINLINE void h_hookMe2() {
	std::cout << "Hook 2 Called!" << std::endl;
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe2Tramp, &hookMe2)();
}

unsigned char hookMe3[] = { 
0x57, // push rdi 
0x74,0xf9,
0x74, 0xf0,//je 0x0
0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x90,
0xc3
};

unsigned char hookMe4[] = {
	0x57, // push rdi
	0x48, 0x83, 0xec, 0x30, //sub rsp, 0x30
	0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90,
	0x74,0xf2, //je 0x0
	0xc3
};

NOINLINE void h_nullstub() {
	volatile int i = 0;
}

TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]") {
	PLH::CapstoneDisassembler dis(PLH::Mode::x64);

	SECTION("Normal function") {
		PLH::x64Detour detour((char*)&hookMe1, (char*)&h_hookMe1, dis);
		REQUIRE(detour.hook() == true);
		hookMe1Tramp = detour.getTrampoline();

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("Loop function") {
		PLH::x64Detour detour((char*)&hookMe2, (char*)&h_hookMe2, dis);
		REQUIRE(detour.hook() == true);
		hookMe2Tramp = detour.getTrampoline();

		effects.PushEffect();
		hookMe2();
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("Jmp into prol w/src in range") {
		PLH::x64Detour detour((char*)&hookMe3, (char*)&h_nullstub, dis);
		REQUIRE(detour.hook() == true);
	}

	SECTION("Jmp into prol w/src out of range") {
		PLH::x64Detour detour((char*)&hookMe4, (char*)&h_nullstub, dis);
		REQUIRE(detour.hook() == true);
	}
}