////
//// Created by steve on 7/9/18.
////
//#include <memory>
//
//#include <Catch.hpp>
//
//#include "polyhook2/Exceptions/BreakPointHook.hpp"
//#include "polyhook2/tests/TestEffectTracker.hpp"
//
//EffectTracker effects2;
//
//NOINLINE int hookMe() {
//	volatile int i = 0;
//	i += 1;
//	i += 2;
//	return i;
//}
//
//std::shared_ptr<PLH::BreakPointHook> bpHook; // must be ptr because we need to call getProtectionObject
//NOINLINE int hookMeCallback() {
//	auto protObj = bpHook->getProtectionObject();
//	volatile int i = 0;
//	i += 1;
//
//	effects2.PeakEffect().trigger();
//	return hookMe(); // just call original yourself now
//}
//
//TEST_CASE("Testing Software Breakpoint", "[AVehHook],[BreakpointHook]") {
//	SECTION("Verify callback is executed") {
//		bpHook = std::make_shared<PLH::BreakPointHook>((char*)&hookMe, (char*)&hookMeCallback);
//		REQUIRE(bpHook->hook() == true);
//		
//		effects2.PushEffect();
//
//		REQUIRE(hookMe() == 3);
//		REQUIRE(effects2.PopEffect().didExecute());
//		bpHook->unHook();
//		bpHook.reset();
//	}
//
//	SECTION("Verify multiple calls in a row reprotect") {
//		bpHook = std::make_shared<PLH::BreakPointHook>((char*)&hookMe, (char*)&hookMeCallback);
//		REQUIRE(bpHook->hook() == true);
//
//		effects2.PushEffect();
//		REQUIRE(hookMe() == 3);
//		REQUIRE(effects2.PopEffect().didExecute());
//
//		effects2.PushEffect();
//		REQUIRE(hookMe() == 3);
//		REQUIRE(effects2.PopEffect().didExecute());
//
//		effects2.PushEffect();
//		REQUIRE(hookMe() == 3);
//		REQUIRE(effects2.PopEffect().didExecute());
//		bpHook->unHook();
//	}
//}