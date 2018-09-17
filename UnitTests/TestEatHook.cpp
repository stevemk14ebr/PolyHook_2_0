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