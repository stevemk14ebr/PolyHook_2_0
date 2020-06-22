//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/ZydisDisassembler.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

EffectTracker effects;

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

NOINLINE void hookMe1() {
	PLH::StackCanary canary;
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
	PLH::StackCanary canary;
	std::cout << "Hook 1 Called!" << std::endl;
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe1Tramp, &hookMe1)();
}

NOINLINE void hookMe2() {
	PLH::StackCanary canary;
	for (int i = 0; i < 10; i++) {
		printf("%d\n", i);
	}
}
uint64_t hookMe2Tramp = NULL;

NOINLINE void h_hookMe2() {
	PLH::StackCanary canary;
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

uint64_t nullTramp = NULL;
NOINLINE void h_nullstub() {
	PLH::StackCanary canary;
	volatile int i = 0;
	PH_UNUSED(i);
}

#include <stdlib.h>
uint64_t hookMallocTramp = NULL;
NOINLINE void* h_hookMalloc(size_t size) {
	PLH::StackCanary canary;
	volatile int i = 0;
	PH_UNUSED(i);
	effects.PeakEffect().trigger();

	return PLH::FnCast(hookMallocTramp, &malloc)(size);
}

uint64_t oCreateMutexExA = 0;
HANDLE
WINAPI
hCreateMutexExA(
	_In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_opt_ LPCSTR lpName,
	_In_ DWORD dwFlags,
	_In_ DWORD dwDesiredAccess
) {
	PLH::StackCanary canary;
	printf("kernel32!CreateMutexExA  Name:%s",  lpName);
	return PLH::FnCast(oCreateMutexExA, &CreateMutexExA)(lpMutexAttributes, lpName, dwFlags, dwDesiredAccess);
}

TEMPLATE_TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	TestType dis(PLH::Mode::x64);

	SECTION("Normal function") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe1, (char*)&h_hookMe1, &hookMe1Tramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	// In release mode win apis usually go through two levels of jmps 
	/*
	0xe9 ... jmp iat_thunk

	iat_thunk:
	0xff 25 ... jmp [api_implementation]

	api_implementation:
	    sub rsp, ...
		... the goods ...
	*/
	SECTION("WinApi Indirection") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&CreateMutexExA, (char*)&hCreateMutexExA, &oCreateMutexExA, dis);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Loop function") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe2, (char*)&h_hookMe2, &hookMe2Tramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe2();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src in range") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe3, (char*)&h_nullstub, &nullTramp, dis);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src out of range") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe4, (char*)&h_nullstub, &nullTramp, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("hook malloc") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&malloc, (char*)&h_hookMalloc, &hookMallocTramp, dis);
		effects.PushEffect(); // catch does some allocations, push effect first so peak works
		bool result = detour.hook();

		REQUIRE(result == true);

		void* pMem = malloc(16);
		free(pMem);
		detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
		REQUIRE(effects.PopEffect().didExecute());
	}
}