#include <Catch.hpp>

#include "polyhook2/PE/EatHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

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

TEST_CASE("Eat Hook Tests", "[EatHook]") {
	SECTION("Verify if export is found and hooked") {
		PLH::StackCanary canary;
		PLH::EatHook hook("EatTestExport", L"", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		REQUIRE(hook.hook());

		tEatTestExport pExport = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		REQUIRE(pExport);  

		eatEffectTracker.PushEffect();
		pExport();	
		REQUIRE(eatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify if export is found and hooked when module explicitly named") {
		PLH::StackCanary canary;
		PLH::EatHook hook("EatTestExport", L"Polyhook_2.exe", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		REQUIRE(hook.hook());

		tEatTestExport pExport = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		REQUIRE(pExport);

		eatEffectTracker.PushEffect();
		pExport();
		REQUIRE(eatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}

typedef  int(__stdcall* tEatMessageBox)(HWND    hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT    uType);
uint64_t  oEatMessageBox;

int __stdcall hkEatMessageBox(HWND    hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT    uType)
{
	UNREFERENCED_PARAMETER(lpText);
	UNREFERENCED_PARAMETER(lpCaption);
	UNREFERENCED_PARAMETER(uType);
	UNREFERENCED_PARAMETER(hWnd);
	PLH::StackCanary canary;
	tEatMessageBox MsgBox = (tEatMessageBox)oEatMessageBox;
	MsgBox(0, "My Hook", "text", 0);
	eatEffectTracker.PeakEffect().trigger();
	return 1;
}

TEST_CASE("Eat winapi tests", "[EatHook]") {
	PLH::StackCanary canary;
	LoadLibrary("User32.dll");

	PLH::EatHook hook("MessageBoxA", L"User32.dll", (char*)&hkEatMessageBox, (uint64_t*)&oEatMessageBox);
	REQUIRE(hook.hook());

	eatEffectTracker.PushEffect();

	// force walk of EAT
	tEatMessageBox MsgBox = (tEatMessageBox)GetProcAddress(GetModuleHandleA("User32.dll"), "MessageBoxA");
	MsgBox(0, "test", "test", 0);
	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	hook.unHook();
}

typedef  void(__stdcall* tEatGetSystemTime)(PSYSTEMTIME systemTime);
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

TEST_CASE("Eat winapi multiple hook", "[EatHook]") {
	// These are out of module hooks that require a trampoline stub.
	// Multiple hooks can fail if the trampoline region isn't re-used 
	// across multiple calls. Or if no free block is found at all
	PLH::StackCanary canary;
	PLH::EatHook hook_GST("GetSystemTime", L"kernel32.dll", (char*)&hkGetSystemTime, (uint64_t*)&oEatGetSystemTime);
	REQUIRE(hook_GST.hook());
	eatEffectTracker.PushEffect();

	tEatGetSystemTime GST = (tEatGetSystemTime)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetSystemTime");
	SYSTEMTIME t;
	memset(&t, 0, sizeof(t));
	GST(&t);
	REQUIRE(eatEffectTracker.PopEffect().didExecute());

	PLH::EatHook hook_GLT("GetLocalTime", L"kernel32.dll", (char*)&hkGetLocalTime, (uint64_t*)&oEatGetLocalTime);
	REQUIRE(hook_GLT.hook());
	eatEffectTracker.PushEffect();

	tEatGetLocalTime GLT = (tEatGetLocalTime)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLocalTime");
	memset(&t, 0, sizeof(t));
	GLT(&t);

	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	hook_GLT.unHook();
	hook_GST.unHook();
}