#include <Catch.hpp>

#include "headers/Detour/ILCallback.hpp"
#pragma warning( disable : 4244)

#include "headers/tests/TestEffectTracker.hpp"

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

EffectTracker effectsNTD64;

typedef int(*Func)(void);
TEST_CASE("Minimal Example", "[AsmJit]") {
	asmjit::JitRuntime rt;                          // Runtime specialized for JIT code execution.

	asmjit::CodeHolder code;                        // Holds code and relocation information.
	code.init(rt.codeInfo());					// Initialize to the same arch as JIT runtime.

	asmjit::x86::Assembler a(&code);                  // Create and attach X86Assembler to `code`.
	a.mov(asmjit::x86::eax, 1);                     // Move one to 'eax' register.
	a.ret();										// Return from function.
	// ----> X86Assembler is no longer needed from here and can be destroyed <----
	
	Func fn;
	asmjit::Error err = rt.add(&fn, &code);         // Add the generated code to the runtime.
	if (err) {
		REQUIRE(false);
	}
	
	int result = fn();                      // Execute the generated code.
	REQUIRE(result == 1);

	// All classes use RAII, all resources will be released before `main()` returns,
	// the generated function can be, however, released explicitly if you intend to
	// reuse or keep the runtime alive, which you should in a production-ready code.
	rt.release(fn);
}

#include "headers/Detour/X64Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

NOINLINE void hookMeInt(int a) {
	volatile int var = 1;
	int var2 = var + a;
	printf("%d %d %I64X\n", var, var2, (uint64_t)_ReturnAddress());
}

NOINLINE void hookMeFloat(float a) {
	float ans = 1.0f;
	ans += a;
	printf("%f %f\n", ans, a); 
}

NOINLINE void hookMeIntFloatDouble(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void myCallback(const PLH::ILCallback::Parameters* p, const uint8_t count) {
	printf("Argument Count: %d\n", count);
	for (int i = 0; i < count; i++) {
		printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, *(int*)p->getArgPtr(i), *(float*)p->getArgPtr(i), *(double*)p->getArgPtr(i));

		// one of the args must be pretty l33t
		float fArg = *(float*)p->getArgPtr(i);
		double dArg = *(double*)p->getArgPtr(i);
		if (*(int*)p->getArgPtr(i) == 1337 || (fArg > 1336.0f && fArg < 1338.0f) || (dArg > 1336.0 && dArg < 1338.0)) {
			effectsNTD64.PeakEffect().trigger();
		}
	}
}

TEST_CASE("Minimal ILCallback", "[AsmJit][ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Integer argument") {
		asmjit::FuncSignatureT<void, int> sig;
		sig.setCallConv(asmjit::CallConv::kIdX86Win64);
		uint64_t JIT = callback.getJitFunc(sig, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		PLH::x64Detour detour((char*)&hookMeInt, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD64.PushEffect();
		hookMeInt(1337);
		REQUIRE(effectsNTD64.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Floating argument") {
		uint64_t JIT = callback.getJitFunc("void", {"float"}, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		PLH::x64Detour detour((char*)&hookMeFloat, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD64.PushEffect();
		hookMeFloat(1337.1337f);
		REQUIRE(effectsNTD64.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments, string parsing types") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		PLH::x64Detour detour((char*)&hookMeIntFloatDouble, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD64.PushEffect();
		hookMeIntFloatDouble(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD64.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}
}


NOINLINE void rw(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD64.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void mySecondCallback(const PLH::ILCallback::Parameters* p, const uint8_t count) {
	printf("Argument Count: %d\n", count);
	for (int i = 0; i < count; i++) {
		printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, *(int*)p->getArgPtr(i), *(float*)p->getArgPtr(i), *(double*)p->getArgPtr(i));

		// re-write to 5 iff it's l33t
		float fArg = *(float*)p->getArgPtr(i);
		double dArg = *(double*)p->getArgPtr(i);
		if (*(int*)p->getArgPtr(i) == 1337) {
			*(int*)p->getArgPtr(i) = 5;
		}
		else if ((fArg > 1336.0f && fArg < 1338.0f)) {
			*(float*)p->getArgPtr(i) = 5.0f;
		}
		else if (dArg > 1336.0 && dArg < 1338.0) {
			*(double*)p->getArgPtr(i) = 5.0;
		}
	}
}

TEST_CASE("ILCallback Argument re-writing", "[ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Int, float, double arguments host") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, &mySecondCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		PLH::x64Detour detour((char*)&rw, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD64.PushEffect();
		rw(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD64.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}
}