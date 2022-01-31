////
//// Created by steve on 7/9/18.
////
//#include <memory>
//
//#include <Catch.hpp>
//
//#include "polyhook2/Exceptions/HWBreakPointHook.hpp"
//#include "polyhook2/tests/TestEffectTracker.hpp"
//
//EffectTracker effects3;
//
//NOINLINE int hookMeHWBP() {
//	volatile int i = 0;
//	i += 1;
//	i += 2;
//	return i;
//}
//
//std::shared_ptr<PLH::HWBreakPointHook> hwBpHook; // must be ptr because we need to call getProtectionObject
//NOINLINE int hookMeCallbackHWBP() {
//	auto protObj = hwBpHook->getProtectionObject();
//	volatile int i = 0;
//	i += 1;
//
//	effects3.PeakEffect().trigger();
//	return hookMeHWBP(); // just call original yourself now
//}
//
//TEST_CASE("Testing Hardware Breakpoints", "[AVehHook],[HWBreakPointHook]") {
//	SECTION("Verify callback is executed") {
//		hwBpHook = std::make_shared<PLH::HWBreakPointHook>((char*)&hookMeHWBP, (char*)&hookMeCallbackHWBP);
//		REQUIRE(hwBpHook->hook() == true);
//
//		effects3.PushEffect();
//		REQUIRE(hookMeHWBP() == 3);
//		REQUIRE(effects3.PopEffect().didExecute());
//		hwBpHook->unHook();
//		hwBpHook.reset();
//	}
//
//	SECTION("Verify multiple calls in a row reprotect") {
//		hwBpHook = std::make_shared<PLH::HWBreakPointHook>((char*)&hookMeHWBP, (char*)&hookMeCallbackHWBP);
//		REQUIRE(hwBpHook->hook() == true);
//
//		effects3.PushEffect();
//		REQUIRE(hookMeHWBP() == 3);
//		REQUIRE(effects3.PopEffect().didExecute());
//
//		effects3.PushEffect();
//		REQUIRE(hookMeHWBP() == 3);
//		REQUIRE(effects3.PopEffect().didExecute());
//
//		effects3.PushEffect();
//		REQUIRE(hookMeHWBP() == 3);
//		REQUIRE(effects3.PopEffect().didExecute());
//		hwBpHook->unHook();
//	}
//}