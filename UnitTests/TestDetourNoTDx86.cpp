#include <Catch.hpp>

#include "headers/Detour/ILCallback.hpp"
#pragma warning( disable : 4244)

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

#include "headers/Detour/X86Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

NOINLINE void hookMeInt(int a) {
	volatile int var = 1;
	int var2 = var + a;
	printf("%d %d\n", var, var2);
}

NOINLINE void hookMeFloat(float a) {
	volatile float ans = 0.0f;
	ans += a;
	printf("%f %f\n", ans, a);
}

NOINLINE void __stdcall hookMeIntFloatDoubleStd(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void __cdecl hookMeIntFloatDoubleCdl(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void __fastcall hookMeIntFloatDoubleFst(int a, float b, double c) {
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
	}
}

TEST_CASE("Minimal ILCallback", "[AsmJit][ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Integer argument") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "int" }, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeInt, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);
		hookMeInt(1337);
		REQUIRE(detour.unHook());
	}

	SECTION("Floating argument") {
		uint64_t JIT = callback.getJitFunc("void", { "float" }, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeFloat, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		hookMeFloat(1337.1337f);
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments standard") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, &myCallback, "stdcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleStd, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		hookMeIntFloatDoubleStd(1337, 1337.1337f, 1337.1337);
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments cdecl") {
		uint64_t JIT = callback.getJitFunc("void", {"int", "float", "double"}, &myCallback, "cdecl");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleCdl, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		hookMeIntFloatDoubleCdl(1337, 1337.1337f, 1337.1337);
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments fastcall") {
		uint64_t JIT = callback.getJitFunc("void", {"int", "float", "double"}, &myCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleFst, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		hookMeIntFloatDoubleFst(1337, 1337.1337f, 1337.1337);
		REQUIRE(detour.unHook());
	}

	SECTION("Verify return address spoofing doesn't crash") {
		PLH::PageAllocator mem(0, 0);
		unsigned char* retBufTmp = (unsigned char*)mem.getBlock(10);
		*(unsigned char*)retBufTmp = 0xC3;

		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, &myCallback, "fastcall", (uint64_t)retBufTmp);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleFst, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		hookMeIntFloatDoubleFst(1337, 1337.1337f, 1337.1337);
		REQUIRE(detour.unHook());
	}
	
}