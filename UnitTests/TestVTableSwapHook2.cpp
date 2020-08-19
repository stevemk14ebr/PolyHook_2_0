#include <memory>
#include <stdexcept>

#include <Catch.hpp>

#include "polyhook2/Virtuals/VTableSwapHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

EffectTracker vTblSwapEffects2;

// original class

class MyClass {
public:
	virtual ~MyClass() {}

	virtual int __stdcall method1(int x) {
		return 2 * x;
	}

	virtual int __stdcall method2(int x, int y) {
		return x + y;
	}
};

// virtual function hooks

int __stdcall myclass_method1(MyClass* pThis, int x);
int __stdcall myclass_method2(MyClass* pThis, int x, int y);

// helper typedefs, and unique_ptr for storing the hook

typedef PLH::VFunc<1, decltype(&myclass_method1)> VMethod1;
typedef PLH::VFunc<2, decltype(&myclass_method2)> VMethod2;
std::unique_ptr<PLH::VTableSwapHook> hook = nullptr;

// hook implementations

NOINLINE int __stdcall myclass_method1(MyClass* pThis, int x) {
	vTblSwapEffects2.PeakEffect().trigger();
	return hook->origFunc<VMethod1>(pThis, x) + 1;
}

NOINLINE int __stdcall myclass_method2(MyClass* pThis, int x, int y) {
	vTblSwapEffects2.PeakEffect().trigger();
	return hook->origFunc<VMethod2>(pThis, x, y) + 2;
}

// test case

TEST_CASE("VTableSwap2 tests", "[VTableSwap2]") {
	auto ClassToHook = std::make_shared<MyClass>();

	SECTION("Verify vtable redirected") {
		PLH::StackCanary canary;
		REQUIRE(ClassToHook->method1(3) == 6);
		REQUIRE(ClassToHook->method2(13, 9) == 22);
		hook = std::make_unique<PLH::VTableSwapHook>(
			reinterpret_cast<uint64_t>(ClassToHook.get()),
			VMethod1(&myclass_method1),
			VMethod2(&myclass_method2));
		REQUIRE(hook->hook());

		vTblSwapEffects2.PushEffect();
		REQUIRE(ClassToHook->method1(3) == 7);
		REQUIRE(vTblSwapEffects2.PopEffect().didExecute());

		vTblSwapEffects2.PushEffect();
		REQUIRE(ClassToHook->method2(13, 9) == 24);
		REQUIRE(vTblSwapEffects2.PopEffect().didExecute());

		REQUIRE(hook->unHook());

		vTblSwapEffects2.PushEffect();
		REQUIRE(ClassToHook->method1(3) == 6);
		REQUIRE(!vTblSwapEffects2.PopEffect().didExecute());

		vTblSwapEffects2.PushEffect();
		REQUIRE(ClassToHook->method2(13, 9) == 22);
		REQUIRE(!vTblSwapEffects2.PopEffect().didExecute());
	}
}