//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>

#include "headers/Exceptions/BreakPointHook.hpp"
#include "headers/tests/TestEffectTracker.hpp"

EffectTracker effects2;

NOINLINE int hookMe() {
	volatile int i = 0;
	i += 1;
	i /= 2;
	return i;
}

NOINLINE void hookMeCallback() {
	volatile int i = 0;
	//effects2.PeakEffect().trigger();
}

TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]") {
	SECTION("Verify callback is executed") {
		PLH::BreakPointHook bp((char*)&hookMe, (char*)&hookMeCallback);
		REQUIRE(bp.hook() == true);

		effects2.PushEffect();
		hookMe();
		printf("worked\n");
		//REQUIRE(effects2.PopEffect().didExecute());
	}
}