#include <Catch.hpp>

#include "polyhook2/Detour/ILCallback.hpp"
#pragma warning( disable : 4244)

#include "polyhook2/Tests/TestEffectTracker.hpp"

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

EffectTracker effectsNTD;

typedef int(*Func)(void);

#include "polyhook2/Detour/x86Detour.hpp"
#include "polyhook2/CapstoneDisassembler.hpp"

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

#ifdef _MSC_VER
	uint32_t retAddress = (uint32_t)_ReturnAddress();
#elif __GNUC__
	uint32_t retAddress = (uint32_t)__builtin_return_address(0);
#else
	#error "Please implement this for your compiler."
#endif

	printf("%d %f %f %f retAddr:%x\n", a, b, c, ans, retAddress);
}

NOINLINE void myCallback(const PLH::ILCallback::Parameters* p, const uint8_t count, const PLH::ILCallback::ReturnValue* retVal) {
	PH_UNUSED(retVal);
	printf("Argument Count: %d\n", count);
	for (int i = 0; i < count; i++) {
		printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, p->getArg<int>(i), p->getArg<float>(i), p->getArg<double>(i));

		// one of the args must be pretty l33t
		float fArg = p->getArg<float>(i);
		double dArg = p->getArg<double>(i);
		if (p->getArg<int>(i) == 1337 || (fArg > 1336.0f && fArg < 1338.0f) || (dArg > 1336.0 && dArg < 1338.0)) {
			effectsNTD.PeakEffect().trigger();
		}
	}
}

TEST_CASE("Minimal ILCallback", "[AsmJit][ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Integer argument") {
		uint64_t JIT = callback.getJitFunc("void", { "int" }, asmjit::Environment::kArchHost, &myCallback);
		REQUIRE(JIT != 0);
		
		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeInt, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeInt(1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Floating argument") {
		uint64_t JIT = callback.getJitFunc("void", { "float" }, asmjit::Environment::kArchHost, &myCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeFloat, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeFloat(1337.1337f);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments standard") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &myCallback, "stdcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleStd, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeIntFloatDoubleStd(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments cdecl") {
		uint64_t JIT = callback.getJitFunc("void", {"int", "float", "double"}, asmjit::Environment::kArchHost, &myCallback, "cdecl");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleCdl, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeIntFloatDoubleCdl(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments fastcall") {
		uint64_t JIT = callback.getJitFunc("void", {"int", "float", "double"}, asmjit::Environment::kArchHost, &myCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleFst, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeIntFloatDoubleFst(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Verify return address spoofing doesn't crash") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &myCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&hookMeIntFloatDoubleFst, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		hookMeIntFloatDoubleFst(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}
	
}

NOINLINE void __fastcall rw_fst(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void __cdecl rw_cdecl(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void __stdcall rw_std(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void rw_host(int a, float b, double c) {
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
}

NOINLINE void mySecondCallback(const PLH::ILCallback::Parameters* p, const uint8_t count, const PLH::ILCallback::ReturnValue* retVal) {
	PH_UNUSED(retVal);
	printf("Argument Count: %d\n", count);
	for (int i = 0; i < count; i++) {
		printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, p->getArg<int>(i), p->getArg<float>(i), p->getArg<double>(i));

		// re-write to 5 iff it's l33t
		float fArg = p->getArg<float>(i);
		double dArg = p->getArg<double>(i);
		if (p->getArg<int>(i) == 1337) {
			p->setArg<int>(i, 5);
		} else if ((fArg > 1336.0f && fArg < 1338.0f)) {
			p->setArg<float>(i, 5.0f);
		} else if (dArg > 1336.0 && dArg < 1338.0) {
			p->setArg<double>(i, 5.0);
		}
	}
}

TEST_CASE("ILCallback Argument re-writing", "[ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Int, float, double arguments host") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &mySecondCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_host, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		rw_host(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments fastcall") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &mySecondCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_fst, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		rw_fst(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments cdecl") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &mySecondCallback, "cdecl");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_cdecl, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		rw_cdecl(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Int, float, double arguments stdcall") {
		uint64_t JIT = callback.getJitFunc("void", { "int", "float", "double" }, asmjit::Environment::kArchHost, &mySecondCallback, "stdcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_std, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);


		effectsNTD.PushEffect();
		rw_std(1337, 1337.1337f, 1337.1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}
}

NOINLINE int rw_ret_host(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return a;
}

NOINLINE float rw_ret_host_float(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return b;
}

NOINLINE double rw_ret_host_double(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return c;
}

NOINLINE int __fastcall rw_ret_fst_int(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return a;
}

NOINLINE int __cdecl rw_ret_cdecl_int(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return a;
}

NOINLINE int __stdcall rw_ret_std_int(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return a;
}

NOINLINE float __fastcall rw_ret_fst_float(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return b;
}

NOINLINE float __cdecl rw_ret_cdecl_float(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return b;
}

NOINLINE float __stdcall rw_ret_std_float(int a, float b, double c, int usageType) {
	PH_UNUSED(usageType);
	volatile float ans = 0.0f;
	ans += (float)a;
	ans += c;
	ans += b;
	if (a == 5 && (b > 4.0f && b < 6.0f) && (c > 4.0 && c < 6.0)) {
		effectsNTD.PeakEffect().trigger();
	}
	printf("%d %f %f %f\n", a, b, c, ans);
	return b;
}

NOINLINE void myThirdCallback(const PLH::ILCallback::Parameters* p, const uint8_t count, const PLH::ILCallback::ReturnValue* retVal) {
	printf("Argument Count: %d\n", count);
	for (int i = 0; i < count; i++) {
		printf("Arg: %d asInt:%d asFloat:%f asDouble:%f\n", i, p->getArg<int>(i), p->getArg<float>(i), p->getArg<double>(i));

		// re-write to 5 iff it's l33t
		float fArg = p->getArg<float>(i);
		double dArg = p->getArg<double>(i);
		if (p->getArg<int>(i) == 1337) {
			p->setArg<int>(i, 5);
		}
		else if ((fArg > 1336.0f && fArg < 1338.0f)) {
			p->setArg<float>(i, 5.0f);
		}
		else if (dArg > 1336.0 && dArg < 1338.0) {
			p->setArg<double>(i, 5.0);
		}
	}

	// little hack, use 4th param to test different return types
	switch (p->getArg<int>(3)) {
	case 0:
		*(int*)retVal->getRetPtr() = 1337;
		break;
	case 1:
		*(float*)retVal->getRetPtr() = 1337.0f;
		break;
	case 2:
		*(double*)retVal->getRetPtr() = 1337.0;
		break;
	default:
		printf("Unknown Mode, NOT modifying ret val!\n");
	}
}

TEST_CASE("ILCallback Return and Argument Re-Writing", "[ILCallback]") {
	PLH::ILCallback callback;

	SECTION("Minimal host, int, float, double, int return") {
		uint64_t JIT = callback.getJitFunc("int", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_host, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 0 is int type
		int val = rw_ret_host(1337, 1337.1337f, 1337.1337, 0);
		REQUIRE(val == 1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Minimal host, int, float, double, float return") {
		uint64_t JIT = callback.getJitFunc("float", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_host_float, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 1 is float type
		float val = rw_ret_host_float(1337, 1337.1337f, 1337.1337, 1);
		REQUIRE(val == Approx(1337.0f));
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("Minimal host, int, float, double, double return") {
		uint64_t JIT = callback.getJitFunc("double", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback);
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_host_double, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 2 is double type
		double val = rw_ret_host_double(1337, 1337.1337f, 1337.1337, 2);
		REQUIRE(val == Approx(1337.0));
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}


	SECTION("int, float, double, int return, stdcall") {
		uint64_t JIT = callback.getJitFunc("int", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "stdcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_std_int, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 0 is int type
		int val = rw_ret_std_int(1337, 1337.1337f, 1337.1337, 0);
		REQUIRE(val == 1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}


	SECTION("int, float, double, int return, cdecl") {
		uint64_t JIT = callback.getJitFunc("int", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "cdecl");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_cdecl_int, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 0 is int type
		int val = rw_ret_cdecl_int(1337, 1337.1337f, 1337.1337, 0);
		REQUIRE(val == 1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("int, float, double, int return, fastcall") {
		uint64_t JIT = callback.getJitFunc("int", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_fst_int, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();
		// 0 is int type
		int val = rw_ret_fst_int(1337, 1337.1337f, 1337.1337, 0);
		REQUIRE(val == 1337);
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("int, float, double, float return, fastcall") {
		uint64_t JIT = callback.getJitFunc("float", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "fastcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_fst_float, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();

		// 1 is float type
		float val = rw_ret_fst_float(1337, 1337.1337f, 1337.1337, 1);
		REQUIRE(val == Approx(1337.0f));
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("int, float, double, float return, cdecl") {
		uint64_t JIT = callback.getJitFunc("float", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "cdecl");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_cdecl_float, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();

		// 1 is float type
		float val = rw_ret_cdecl_float(1337, 1337.1337f, 1337.1337, 1);
		REQUIRE(val == Approx(1337.0f));
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}

	SECTION("int, float, double, float return, std") {
		uint64_t JIT = callback.getJitFunc("float", { "int", "float", "double", "int" }, asmjit::Environment::kArchHost, &myThirdCallback, "stdcall");
		REQUIRE(JIT != 0);

		PLH::CapstoneDisassembler dis(PLH::Mode::x86);
		PLH::x86Detour detour((char*)&rw_ret_std_float, (char*)JIT, callback.getTrampolineHolder(), dis);
		REQUIRE(detour.hook() == true);

		effectsNTD.PushEffect();

		// 1 is float type
		float val = rw_ret_std_float(1337, 1337.1337f, 1337.1337, 1);
		REQUIRE(val == Approx(1337.0f));
		REQUIRE(effectsNTD.PopEffect().didExecute());
		REQUIRE(detour.unHook());
	}
}