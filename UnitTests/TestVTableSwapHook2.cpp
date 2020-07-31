#include <memory>
#include <stdexcept>

#include <Catch.hpp>

#include "polyhook2/Virtuals/VTableSwapHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"

// original class

class MyClass {
public:
	virtual ~MyClass() {}

	virtual int method1(int x) {
		return 2 * x;
	}

	virtual int method2(int x, int y) {
		return x + y;
	}
};

// virtual function hooks

int myclass_method1(MyClass* pThis, int x);
int myclass_method2(MyClass* pThis, int x, int y);

// helper typedefs, and unique_ptr for storing the hook

typedef PLH::VFunc<1, decltype(&myclass_method1)> VMethod1;
typedef PLH::VFunc<2, decltype(&myclass_method2)> VMethod2;
typedef PLH::VTableSwapHook2<MyClass, VMethod1, VMethod2> VTableMyClass;
std::unique_ptr<VTableMyClass> hook = nullptr;

// hook implementations

NOINLINE int myclass_method1(MyClass* pThis, int x) {
	if (!hook)
		throw std::runtime_error("original function not hooked");
	return hook->origFunc<VMethod1>(pThis, x) + 1;
}

NOINLINE int myclass_method2(MyClass* pThis, int x, int y) {
	if (!hook)
		throw std::runtime_error("original function not hooked");
	return hook->origFunc<VMethod2>(pThis, x, y) + 2;
}

// test case

TEST_CASE("VTableSwap2 tests", "[VTableSwap2]") {
	std::shared_ptr<MyClass> pClass(new MyClass); 

	SECTION("Verify vtable redirected") {
		PLH::StackCanary canary;
		REQUIRE(pClass->method1(3) == 6);
		REQUIRE(pClass->method2(13, 9) == 22);
		hook = std::make_unique<VTableMyClass>(pClass.get(), VMethod1(&myclass_method1), VMethod2(&myclass_method2));
		REQUIRE(pClass->method1(3) == 7);
		REQUIRE(pClass->method2(13, 9) == 24);
		hook = nullptr;
		REQUIRE(pClass->method1(3) == 6);
		REQUIRE(pClass->method2(13, 9) == 22);
	}
}