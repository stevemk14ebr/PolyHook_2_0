#include <Catch.hpp>

#include "headers/PE/EatHook.hpp"
#include "headers/Tests/TestEffectTracker.hpp"

EffectTracker eatEffectTracker;

typedef void(* tEatTestExport)();
tEatTestExport oEatTestExport;

extern "C" __declspec(dllexport) NOINLINE void EatTestExport()
{
}

NOINLINE void hkEatTestExport()
{	
	eatEffectTracker.PeakEffect().trigger();
}

TEST_CASE("Eat Hook Tests", "[EatHook]") {
	SECTION("Verify if export is found and hooked") {
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
tEatMessageBox  oEatMessageBox;

int __stdcall hkEatMessageBox(HWND    hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT    uType)
{
	UNREFERENCED_PARAMETER(lpText);
	UNREFERENCED_PARAMETER(lpCaption);
	UNREFERENCED_PARAMETER(uType);
	UNREFERENCED_PARAMETER(hWnd);

	MessageBox(0, "My Hook", "text", 0);
	eatEffectTracker.PeakEffect().trigger();
	return 1;
}

TEST_CASE("Eat winapi tests", "[EatHook]") {
	PLH::EatHook hook("MessageBoxA", L"User32.dll", (char*)&hkEatMessageBox, (uint64_t*)&oEatMessageBox);
	REQUIRE(hook.hook());

	eatEffectTracker.PushEffect();
	MessageBoxA(0, "test", "test", 0);
	REQUIRE(eatEffectTracker.PopEffect().didExecute());
	hook.unHook();
}