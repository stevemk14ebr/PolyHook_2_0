//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "polyhook2/Detour/x86Detour.hpp"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/ZydisDisassembler.hpp"

#include "polyhook2/Tests/TestEffectTracker.hpp"

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

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
unsigned char hookMe2[] = {0x55, 0x8b, 0xec, 0x74, 0xFB, 0x74, 0xea, 0x74, 0xFA, 0x8b, 0xec,0x8b, 0xec,0x8b, 0xec,0x90, 0x90, 0x90, 0x90, 0x90};
uint64_t nullTramp = NULL;
NOINLINE void __cdecl h_nullstub() {
	volatile int i = 0;
	PH_UNUSED(i);
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
unsigned char hookMe3[] = {0x55, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x90, 0x90, 0x7F, 0xF4};

NOINLINE void PH_ATTR_NAKED hookMeLoop() {
#ifdef _MSC_VER
	__asm {
		xor eax, eax
		start :
		inc eax
			cmp eax, 5
			jle start
			ret
	}
#elif __GNUC__
	asm(
		"xor %eax, %eax;\n\t"
		"START: inc %eax;\n\t"
		"cmp $5, %eax;\n\t"
		"jle START;\n\t"
		"ret;"
	);
#else
#error "Please implement this for your compiler!"
#endif
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

#include <stdlib.h>
uint64_t hookMallocTramp = NULL;
NOINLINE void* h_hookMalloc(size_t size) {
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMallocTramp, &malloc)(size);
}

TEMPLATE_TEST_CASE("Testing x86 detours", "[x86Detour],[ADetour]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	TestType dis(PLH::Mode::x86);

	SECTION("Normal function") {
		PLH::x86Detour detour((char*)&hookMe1, (char*)&h_hookMe1, &hookMe1Tramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		volatile auto result = hookMe1();
		PH_UNUSED(result);
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prologue w/ src in range") {
		PLH::x86Detour detour((char*)&hookMe2, (char*)&h_nullstub, &nullTramp, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prologue w/ src out of range") {
		PLH::x86Detour detour((char*)&hookMe3, (char*)&h_nullstub, &nullTramp, dis);
		//hookMe1Tramp = detour.getTrampoline();
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Loop") {
		PLH::x86Detour detour((char*)&hookMeLoop, (char*)&h_hookMeLoop, &hookMeLoopTramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMeLoop();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("hook printf") {
		PLH::x86Detour detour((char*)&printf, (char*)&h_hookPrintf, &hookPrintfTramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		printf("%s %f\n", "hi", .5f);
		detour.unHook();
		REQUIRE(effects.PopEffect().didExecute());
	}

	// it's a pun...
	SECTION("hook pow") {
		PLH::x86Detour detour((char*)pFnPowDouble, (char*)&h_hookPow, &hookPowTramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		volatile double result = pFnPowDouble(2, 2);
		PH_UNUSED(result);
		detour.unHook();
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("hook malloc") {
		PLH::x86Detour detour((char*)&malloc, (char*)&h_hookMalloc, &hookMallocTramp, dis);
		effects.PushEffect(); // catch does some allocations, push effect first so peak works
		REQUIRE(detour.hook() == true);

		void* pMem = malloc(16);
		free(pMem);
		detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
		REQUIRE(effects.PopEffect().didExecute());
	}
}
