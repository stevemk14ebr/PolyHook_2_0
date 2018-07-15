//
// Created by steve on 7/9/18.
//
#include <memory>

#include <Catch.hpp>

#include "headers/Exceptions/BreakPointHook.hpp"
#include "headers/tests/TestEffectTracker.hpp"

template <typename T>
struct return_type;
template <typename R, typename... Args>
struct return_type<R(*)(Args...)> { using type = R; };
template <typename R, typename C, typename... Args>
struct return_type<R(C::*)(Args...)> { using type = R; };
template <typename R, typename C, typename... Args>
struct return_type<R(C::*)(Args...) const> { using type = R; };
template <typename R, typename C, typename... Args>
struct return_type<R(C::*)(Args...) volatile> { using type = R; };
template <typename R, typename C, typename... Args>
struct return_type<R(C::*)(Args...) const volatile> { using type = R; };
template <typename T>
using return_type_t = typename return_type<T>::type;

EffectTracker effects2;

NOINLINE int hookMe() {
	volatile int i = 0;
	i += 1;
	i += 2;
	return i;
}

std::shared_ptr<PLH::BreakPointHook> bpHook;
NOINLINE int hookMeCallback() {
	auto protObj = bpHook->getProtectionObject();
	volatile int i = 0;

	effects2.PeakEffect().trigger();
	return hookMe(); // just call original yourself now
}

TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]") {
	SECTION("Verify callback is executed") {
		bpHook = std::make_shared<PLH::BreakPointHook>((char*)&hookMe, (char*)&hookMeCallback);
		REQUIRE(bpHook->hook() == true);
		
		effects2.PushEffect();
		REQUIRE(hookMe() == 3);
		REQUIRE(effects2.PopEffect().didExecute());
		bpHook->unHook();
	}

	SECTION("Verify multiple calls in a row reprotect") {
		bpHook = std::make_shared<PLH::BreakPointHook>((char*)&hookMe, (char*)&hookMeCallback);
		REQUIRE(bpHook->hook() == true);

		effects2.PushEffect();
		REQUIRE(hookMe() == 3);
		REQUIRE(effects2.PopEffect().didExecute());

		effects2.PushEffect();
		REQUIRE(hookMe() == 3);
		REQUIRE(effects2.PopEffect().didExecute());

		effects2.PushEffect();
		REQUIRE(hookMe() == 3);
		REQUIRE(effects2.PopEffect().didExecute());
		bpHook->unHook();
	}
}