//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "headers/Detour/x86Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

#include "headers/tests/TestEffectTracker.hpp"

EffectTracker effects;

NOINLINE int __cdecl hookMe1() {
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
	return var;
}

uint64_t hookMe1Tramp = NULL;
NOINLINE int __cdecl h_hookMe1() {
	std::cout << "Hook 1 Called!" << std::endl;

	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe1Tramp, &hookMe1)();
}

/*  55                      push   ebp
1:  8b ec                   mov    ebp,esp
3:  74 fb                   je     0x0
5:  74 fa                   je     0x1
7:  8b ec                   mov    ebp,esp
9:  8b ec                   mov    ebp,esp
b:  8b ec                   mov    ebp,esp
d:  90                      nop
e:  90                      nop
f:  90                      nop
10: 90                      nop
11: 90                      nop */
unsigned char hookMe2[] = {0x55, 0x8b, 0xec, 0x74, 0xFB, 0x74, 0xea, 0x74, 0xFA, 0x8b, 0xec,0x8b, 0xec,0x8b, 0xec,0x90, 0x90, 0x90, 0x90, 0x90 };
NOINLINE void __cdecl h_nullstub() {
	volatile int i = 0;
}

/*
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  89 e5                   mov    ebp,esp
5:  89 e5                   mov    ebp,esp
7:  89 e5                   mov    ebp,esp
9:  90                      nop
a:  90                      nop
b:  7f f4                   jg     0x1
*/
unsigned char hookMe3[] = { 0x55, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x90, 0x90, 0x7F, 0xF4 };

NOINLINE void __declspec(naked) hookMeLoop() {
	__asm {
		xor eax, eax
	start:
		inc eax
		cmp eax, 5
		jle start
		ret
	}
}

uint64_t hookMeLoopTramp = NULL;
NOINLINE void __stdcall h_hookMeLoop() {
	std::cout << "Hook loop Called!" << std::endl;

	effects.PeakEffect().trigger();
	PLH::FnCast(hookMeLoopTramp, &hookMeLoop)();
}

#include <cstdarg>
uint64_t hookPrintfTramp = NULL;
NOINLINE int __cdecl h_hookPrintf(const char* format, ...) {
	char buffer[512];
	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);

	effects.PeakEffect().trigger();
	return PLH::FnCast(hookPrintfTramp, &printf)("INTERCEPTED YO:%s", buffer);
}

#include <cmath>
// must specify specific overload of std::pow by assiging to pFn of type
double(*pFnPowDouble)(double, double) = &std::pow;

uint64_t hookPowTramp = NULL;
NOINLINE double __cdecl h_hookPow(double X, double Y) {
	effects.PeakEffect().trigger();

	return PLH::FnCast(hookPowTramp, pFnPowDouble)(X, Y);
}

TEST_CASE("Testing x86 detours", "[x86Detour],[ADetour]") {
	PLH::CapstoneDisassembler dis(PLH::Mode::x86);

	SECTION("Normal function") {
		PLH::x86Detour detour((char*)&hookMe1, (char*)&h_hookMe1, dis);
		REQUIRE(detour.hook() == true);
		hookMe1Tramp = detour.getTrampoline();

		effects.PushEffect();
		volatile auto result = hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("Jmp into prologue w/ src in range") {
		PLH::x86Detour detour((char*)&hookMe2, (char*)&h_nullstub, dis);
		//hookMe1Tramp = detour.getTrampoline();
		REQUIRE(detour.hook() == true);
	}

	SECTION("Jmp into prologue w/ src out of range") {
		PLH::x86Detour detour((char*)&hookMe3, (char*)&h_nullstub, dis);
		//hookMe1Tramp = detour.getTrampoline();
		REQUIRE(detour.hook() == true);
	}

	SECTION("Loop") {
		PLH::x86Detour detour((char*)&hookMeLoop, (char*)&h_hookMeLoop, dis);
		REQUIRE(detour.hook() == true);
		hookMeLoopTramp = detour.getTrampoline();

		effects.PushEffect();
		hookMeLoop();
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("hook printf") {
		PLH::x86Detour detour((char*)&printf, (char*)&h_hookPrintf, dis);
		REQUIRE(detour.hook() == true);
		hookPrintfTramp = detour.getTrampoline();

		effects.PushEffect();
		printf("%s %f\n", "hi", .5f);
		REQUIRE(effects.PopEffect().didExecute());
	}

	// it's a pun...
	SECTION("hook pow") {
		PLH::x86Detour detour((char*)pFnPowDouble, (char*)&h_hookPow, dis);
		REQUIRE(detour.hook() == true);
		hookPowTramp = detour.getTrampoline();

		effects.PushEffect();
		volatile double result = pFnPowDouble(2, 2);
		REQUIRE(effects.PopEffect().didExecute());
	}
}
