#include <Catch.hpp>

#include "headers/PE/EatHook.hpp"
#include "headers/Tests/TestEffectTracker.hpp"

EffectTracker eatEffectTracker;

typedef void(__stdcall* tEatTestExport)();
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
		PLH::EatHook hook(L"PolyHook_2.exe", "EatTestExport", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		REQUIRE(hook.hook());

		tEatTestExport pExport = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		REQUIRE(pExport);  

		eatEffectTracker.PushEffect();
		pExport();	
		REQUIRE(eatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}