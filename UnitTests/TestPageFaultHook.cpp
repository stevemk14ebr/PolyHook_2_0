//
// Created by steve on 7/9/18.
//
#include <memory>

#include <Catch.hpp>

#include "headers/Exceptions/PageFaultHook.hpp"
#include "headers/tests/TestEffectTracker.hpp"

EffectTracker effects4;

NOINLINE int hookMePFT() {
	volatile int i = 0;
	i += 1;
	i += 2;
	return i;
}

std::shared_ptr<PLH::PageFaultHook> pftHook; // must be ptr because we need to call getProtectionObject
NOINLINE int hookMePFTCallback() {
	auto protObj = pftHook->getProtectionObject();
	volatile int i = 0;
	i += 1;

	printf("Execute pft callback\n");

	effects4.PeakEffect().trigger();
	return hookMePFT(); // just call original yourself now
}

TEST_CASE("Testing PageFault hook", "[AVehHook],[PageFaultHook]") {
	SECTION("Verify callback is executed") {
		pftHook = std::make_shared<PLH::PageFaultHook>((char*)&hookMePFT, (char*)&hookMePFTCallback);
		pftHook->hook();

		/*effects4.PushEffect();
		REQUIRE(hookMePFT() == 3);
		REQUIRE(effects4.PopEffect().didExecute());*/
	}

	//SECTION("Verify multiple calls in a row reprotect") {
	//	pftHook = std::make_shared<PLH::PageFaultHook>((char*)&hookMePFT, (char*)&hookMePFTCallback);
	//	REQUIRE(pftHook->hook() == true);

	//	effects4.PushEffect();
	//	REQUIRE(hookMePFT() == 3);
	//	REQUIRE(effects4.PopEffect().didExecute());

	//	effects4.PushEffect();
	//	REQUIRE(hookMePFT() == 3);
	//	REQUIRE(effects4.PopEffect().didExecute());

	//	effects4.PushEffect();
	//	REQUIRE(hookMePFT() == 3);
	//	REQUIRE(effects4.PopEffect().didExecute());
	//	pftHook->unHook();
	//}
}