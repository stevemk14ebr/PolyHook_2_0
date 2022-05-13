#include <memory>

#include <Catch.hpp>

#include "polyhook2/Virtuals/VTableSwapHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

EffectTracker vTblSwapEffects;

class VirtualTest {
public:
	virtual ~VirtualTest() {}

	virtual int __stdcall NoParamVirt() {
		return 4;
	}

	virtual int __stdcall NoParamVirt2() {
		return 7;
	}
};

#pragma warning(disable: 4100)
PLH::VFuncMap origVFuncs;
HOOK_CALLBACK(&VirtualTest::NoParamVirt, hkVirtNoParams, {
	vTblSwapEffects.PeakEffect().trigger();
	return ((hkVirtNoParams_t)origVFuncs.at(1))(_args...);
});

HOOK_CALLBACK(&VirtualTest::NoParamVirt2, hkVirt2NoParams, {
	vTblSwapEffects.PeakEffect().trigger();
	return ((hkVirt2NoParams_t)origVFuncs.at(2))(_args...);
});

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);

	SECTION("Verify vtable redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams}};
		PLH::VTableSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs.size() == 1);

		vTblSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vTblSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify multiple vtable redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams},{(uint16_t)2, (uint64_t)hkVirtNoParams}};
		PLH::VTableSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs.size() == 2);

		vTblSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vTblSwapEffects.PopEffect().didExecute());

		vTblSwapEffects.PushEffect();
		ClassToHook->NoParamVirt2();
		REQUIRE(vTblSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}