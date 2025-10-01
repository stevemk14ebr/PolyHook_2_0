// NOLINTBEGIN(*-err58-cpp)
#include <cstdarg>

#include <Catch.hpp>

#include "polyhook2/Detour/x86Detour.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "../TestUtils.hpp"

namespace {

EffectTracker effects;

constexpr uint8_t JUMP_SIZE = 5;

}

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

PLH_TEST_DETOUR_CALLBACK(hookMe1, {
	std::cout << "Hook 1 Called! Trampoline: 0x" << std::hex << hookMe1_trmp << std::endl;
});

unsigned char hookMe2[] = {
	0x55,		// [00] push ebp
	0x8b, 0xec, // [01] mov  ebp,esp
	0x74, 0xfb, // [03] je   0x0
	0x74, 0xfa, // [05] je   0x1
	0x8b, 0xec, // [07] mov  ebp,esp
	0x8b, 0xec, // [09] mov  ebp,esp
	0x8b, 0xec, // [0B] mov  ebp,esp
	0x90,		// [0D] nop
	0x90,		// [0E] nop
	0x90,		// [0F] nop
	0x90,		// [10] nop
	0x90,		// [11] nop
	0x90,		// [12] nop
};

uint64_t nullTramp = 0;
NOINLINE void h_nullstub() {
	PLH::StackCanary canary;
	PLH_STOP_OPTIMIZATIONS();
}

unsigned char hookMe3[] = {
	0x55,		// [00] push ebp
	0x89, 0xe5, // [01] mov  ebp,esp
	0x89, 0xe5, // [03] mov  ebp,esp
	0x89, 0xe5, // [05] mov  ebp,esp
	0x89, 0xe5, // [07] mov  ebp,esp
	0x90,		// [09] nop
	0x90,		// [0A] nop
	0x7f, 0xf4, // [0B] jg   0x1
	0x90,		// [0D] nop
	0x90,		// [0E] nop
	0x90,		// [0F] nop
	0x90,		// [10] nop
	0x90,		// [11] nop
	0x90,		// [12] nop
};

uint8_t hookMe4[] = {
	0x55,					// push ebp
	0x8b, 0xec,				// mov ebp, esp
	0x56,					// push esi
	0x8b, 0x75, 0x08,		// mov esi, [ebp+8]
	0xf6, 0x46, 0x30, 0x02, // test byte ptr ds:[esi+0x30], 0x2
	0x90, 0x90, 0x90, 0x90, // nop x4
	0x90, 0x90, 0x90, 0x90, // nop x4
	0xc3					// ret
};

// old NtQueueApcThread, call fs:0xC0 was weird
unsigned char hookMe5[] = {
	0xB8, 0X44, 0X00, 0X00, 0X00,			  // mov eax, 0x44
	0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00, // call dword ptr fs:0xc0
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nop x7
	0xc2, 0x14, 0x00						  // retn 0x14
};

NOINLINE void PH_ATTR_NAKED hookMeLoop() {
	asm("xor %eax, %eax;\n"
		"START: inc %eax;\n"
		"cmp $5, %eax;\n"
		"jle START;\n"
		"ret;");
}

extern "C" NOINLINE uintptr_t PH_ATTR_NAKED returnESP() {
	__asm__ __volatile__ (
		"movl (%esp), %eax\n"
		"ret"
	);
}

NOINLINE uintptr_t PH_ATTR_NAKED readESP() {
	__asm__ __volatile__ (
		"call returnESP\n"
		"ret"
	);
}
PLH_TEST_DETOUR_CALLBACK(readESP);

NOINLINE uintptr_t PH_ATTR_NAKED inlineReadESP() {
	__asm__ __volatile__ (
		"call 0f\n"
		"0: pop %%eax\n"
		"ret"
		::: "eax"
	);
}
PLH_TEST_DETOUR_CALLBACK(inlineReadESP);

PLH_TEST_DETOUR_CALLBACK(hookMeLoop);

// PLH_TEST_DETOUR_CALLBACK doesn't support variadic functions yet.
uint64_t hookPrintfTramp = 0;
NOINLINE int h_hookPrintf(const char *format, ...) {
	char buffer[512];
	va_list args;
	va_start(args, format);
	const auto written = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	const std::string message = {buffer, static_cast<size_t>(written)};

	effects.PeakEffect().trigger();
	return PLH::FnCast(hookPrintfTramp, &printf)("INTERCEPTED YO:%s", message.c_str());
}

// must specify specific overload of std::pow by assigning to pFn of type
const auto &pow_double = std::pow<double, double>;
PLH_TEST_DETOUR_CALLBACK(pow_double);

PLH_TEST_DETOUR_CALLBACK(malloc);

#include <sys/socket.h>
PLH_TEST_DETOUR_CALLBACK(recv);

TEST_CASE("Testing x86 detours", "[x86Detour][ADetour]") {
	PLH::test::registerTestLogger();

	SECTION("Normal function") {
		PLH::StackCanary canary;
		PLH::x86Detour PLH_TEST_DETOUR(hookMe1);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		volatile auto result = hookMe1();
		PH_UNUSED(result);
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Normal function rehook") {
		PLH::StackCanary canary;
		PLH::x86Detour PLH_TEST_DETOUR(hookMe1);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		REQUIRE(detour.reHook() == true); // can only really test this doesn't cause memory corruption easily
		volatile auto result = hookMe1();
		REQUIRE(result == 2);
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prologue w/ src in range") {
		PLH::x86Detour detour((uint64_t)&hookMe2, (uint64_t)&h_nullstub, &nullTramp);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prologue w/ src out of range") {
		PLH::x86Detour detour((uint64_t)&hookMe3, (uint64_t)&h_nullstub, &nullTramp);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Test instruction in prologue") {
		PLH::x86Detour detour((uint64_t)&hookMe4, (uint64_t)&h_nullstub, &nullTramp);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Call with fs base") {
		PLH::x86Detour detour((uint64_t)&hookMe5, (uint64_t)&h_nullstub, &nullTramp);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Loop") {
		PLH::x86Detour PLH_TEST_DETOUR(hookMeLoop);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMeLoop();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Test #215 (call to routine returning ESP)") {
		PLH::x86Detour PLH_TEST_DETOUR(readESP);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		const auto esp = readESP();
		REQUIRE(esp == (uintptr_t)readESP + JUMP_SIZE);
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Test #217 (inline call to read ESP)") {
		PLH::x86Detour PLH_TEST_DETOUR(inlineReadESP);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		const auto esp = inlineReadESP();
		REQUIRE(esp == (uintptr_t)inlineReadESP + JUMP_SIZE);
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	// TODO: Test idioms #215 and #217 explicitly

#ifndef NDEBUG
	// This test is disabled in Release builds due to aggressive optimization of compilers.
	// Specifically with clang on Linux the std::pow function is always inlined.
	// Hence, the hooked function is never called.

	// it's a pun...
	// ^ what pun? nothing found on the web >.<
	SECTION("hook pow") {

		PLH::x86Detour PLH_TEST_DETOUR(pow_double);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		volatile double result = pow_double(2, 2);
		REQUIRE(result == 4.0);
		detour.unHook();
		REQUIRE(effects.PopEffect().didExecute());
	}
#endif

	SECTION("hook malloc") {
		PLH::x86Detour PLH_TEST_DETOUR(malloc);
		effects.PushEffect(); // catch does some allocations, push effect first so peak works
		REQUIRE(detour.hook() == true);

		void *pMem = malloc(16);
		free(pMem);
		detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
		REQUIRE(effects.PopEffect().didExecute());
	}

	SECTION("hook recv") {
		PLH::x86Detour PLH_TEST_DETOUR(recv);
		REQUIRE(detour.hook() == true);
	}

	SECTION("hook printf") {
		PLH::x86Detour detour((uint64_t)&printf, (uint64_t)h_hookPrintf, &hookPrintfTramp);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		printf("%s %f\n", "hi", .5f);
		detour.unHook();
		REQUIRE(effects.PopEffect().didExecute());
	}
}

// NOLINTEND(*-err58-cpp)