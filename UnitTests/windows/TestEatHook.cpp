#include <Catch.hpp>

#include "polyhook2/PE/EatHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"
#include "polyhook2/Detour/ADetour.hpp"

EffectTracker eatEffectTracker;

typedef void(* tEatTestExport)();
uint64_t oEatTestExport;

extern "C" __declspec(dllexport) NOINLINE void EatTestExport()
{
	PLH::StackCanary canary;
}

NOINLINE void hkEatTestExport()
{
	PLH::StackCanary canary;
	eatEffectTracker.PeakEffect().trigger();
}

TEST_CASE("Hook internal test export", "[EatHook]") {
	SECTION("Verify if export is found and hooked when module name is empty") {
		PLH::StackCanary canary;
		PLH::EatHook hook("EatTestExport", L"", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		REQUIRE(hook.hook());

		auto pExport = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		REQUIRE(pExport);

		eatEffectTracker.PushEffect();
		pExport();
		REQUIRE(eatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify if export is found and hooked when module name is explicitly given") {
		PLH::StackCanary canary;
		PLH::EatHook hook("EatTestExport", L"Polyhook_2.exe", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		REQUIRE(hook.hook());

		auto pExport = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		REQUIRE(pExport);

		eatEffectTracker.PushEffect();
		pExport();
		REQUIRE(eatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}

typedef int(__stdcall* tEatMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
uint64_t oEatMessageBox;
int __stdcall hkEatMessageBox(HWND, LPCTSTR, LPCTSTR, UINT) {
	PLH::StackCanary canary;
	auto MsgBox = (tEatMessageBox)oEatMessageBox;
	MsgBox(nullptr, TEXT("My Hook"), TEXT("text"), 0);
	eatEffectTracker.PeakEffect().trigger();
	return 1;
}

TEST_CASE("Hook User32.MessageBoxA using module name", "[EatHook]") {
	PLH::StackCanary canary;
	LoadLibrary(TEXT("User32.dll"));

#ifdef UNICODE
	std::string apiName = "MessageBoxW";
#else
	std::string apiName = "MessageBoxA";
#endif
	PLH::EatHook hook(apiName, L"User32.dll", (char*)&hkEatMessageBox, (uint64_t*)&oEatMessageBox);
	REQUIRE(hook.hook());

	eatEffectTracker.PushEffect();

	// force walk of EAT
	auto MsgBox = (tEatMessageBox)GetProcAddress(GetModuleHandleA("User32.dll"), apiName.c_str());
	MsgBox(nullptr, TEXT("test"), TEXT("test"), 0);
	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	hook.unHook();
}


typedef DWORD(__stdcall* tGetTickCount)();
uint64_t oGetTickCount = 0;
DWORD WINAPI hkGetTickCount()
{
	PLH::StackCanary canary;
	eatEffectTracker.PeakEffect().trigger();

	auto result = ((tGetTickCount)oGetTickCount)();
	PLH::Log::log("Original GetTickCount: " + std::to_string(result), PLH::ErrorLevel::INFO);

	return 0x1337;
}

TEST_CASE("Hook Kernel32.GetTickCount using module path", "[EatHook]") {
	PLH::StackCanary canary;

	const auto libHandle = LoadLibrary(TEXT("Kernel32.dll"));
	WCHAR libPath[MAX_PATH];
	GetModuleFileNameW(libHandle, libPath, MAX_PATH);

	constexpr auto apiName = "GetTickCount";

	PLH::EatHook hook(apiName, libPath, (char*) hkGetTickCount, &oGetTickCount);
	REQUIRE(hook.hook());

	eatEffectTracker.PushEffect();

	auto address = (void*) GetProcAddress(libHandle, apiName);
	auto result = ((tGetTickCount) address)();

	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	REQUIRE(result == 0x1337);
	hook.unHook();
}

typedef ULONGLONG(__stdcall* tGetTickCount64)();
uint64_t oGetTickCount64 = 0;
ULONGLONG WINAPI hkGetTickCount64()
{
	PLH::StackCanary canary;
	eatEffectTracker.PeakEffect().trigger();

	auto result = ((tGetTickCount)oGetTickCount64)();
	PLH::Log::log("Original GetTickCount64: " + std::to_string(result), PLH::ErrorLevel::INFO);

	return 0xDEADBEEF;
}

TEST_CASE("Hook Kernel32.GetTickCount64 using module handle", "[EatHook]") {
	PLH::StackCanary canary;

	const auto libHandle = LoadLibrary(TEXT("Kernel32.dll"));

	constexpr auto apiName = "GetTickCount64";

	PLH::EatHook hook(apiName, libHandle, (uint64_t) hkGetTickCount64, &oGetTickCount64);
	REQUIRE(hook.hook());

	eatEffectTracker.PushEffect();

	auto address = (void*) GetProcAddress(libHandle, apiName);
	auto result = ((tGetTickCount64) address)();

	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	REQUIRE(result == 0xDEADBEEF);
	hook.unHook();
}

typedef void(__stdcall* tEatGetSystemTime)(PSYSTEMTIME systemTime);
uint64_t oEatGetSystemTime;
void WINAPI hkGetSystemTime(PSYSTEMTIME systemTime)
{
	PLH::StackCanary canary;
	eatEffectTracker.PeakEffect().trigger();
	((tEatGetSystemTime)oEatGetSystemTime)(systemTime);
}

typedef void(__stdcall* tEatGetLocalTime)(PSYSTEMTIME systemTime);
uint64_t oEatGetLocalTime;
void WINAPI hkGetLocalTime(PSYSTEMTIME systemTime)
{
	PLH::StackCanary canary;
	eatEffectTracker.PeakEffect().trigger();
	((tEatGetLocalTime)oEatGetLocalTime)(systemTime);
}

TEST_CASE("Hook Kernel32.[GetSystemTime,GetLocalTime]", "[EatHook]") {
	// These are out of module hooks that require a trampoline stub.
	// Multiple hooks can fail if the trampoline region isn't re-used
	// across multiple calls. Or if no free block is found at all
	PLH::StackCanary canary;
	PLH::EatHook hook_GST("GetSystemTime", L"kernel32.dll", (char*)&hkGetSystemTime, (uint64_t*)&oEatGetSystemTime);
	REQUIRE(hook_GST.hook());
	eatEffectTracker.PushEffect();

	auto GST = (tEatGetSystemTime)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetSystemTime");
	SYSTEMTIME t;
	memset(&t, 0, sizeof(t));
	GST(&t);
	REQUIRE(eatEffectTracker.PopEffect().didExecute());

	PLH::EatHook hook_GLT("GetLocalTime", L"kernel32.dll", (char*)&hkGetLocalTime, (uint64_t*)&oEatGetLocalTime);
	REQUIRE(hook_GLT.hook());
	eatEffectTracker.PushEffect();

	auto GLT = (tEatGetLocalTime)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLocalTime");
	memset(&t, 0, sizeof(t));
	GLT(&t);

	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	hook_GLT.unHook();
	hook_GST.unHook();
}
