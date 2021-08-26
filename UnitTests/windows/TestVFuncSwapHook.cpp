#include <memory>

#include <Catch.hpp>

#include "polyhook2/Virtuals/VFuncSwapHook.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

EffectTracker vFuncSwapEffects;

class VirtualTest2 {
public:
	virtual ~VirtualTest2() {}

	virtual int __stdcall NoParamVirt() {
		return 4;
	}

	virtual int __stdcall NoParamVirt2() {
		return 7;
	}
};

#pragma warning(disable: 4100)

PLH::VFuncMap origVFuncs2;
HOOK_CALLBACK(&VirtualTest2::NoParamVirt, hkVirtNoParams2, {
	PLH::StackCanary canary;
	vFuncSwapEffects.PeakEffect().trigger();
	return ((hkVirtNoParams2_t)origVFuncs2.at(1))(_args...);
});

HOOK_CALLBACK(&VirtualTest2::NoParamVirt2, hkVirt2NoParams2, {
	PLH::StackCanary canary;
	vFuncSwapEffects.PeakEffect().trigger();
	return ((hkVirtNoParams2_t)origVFuncs2.at(2))(_args...);
});

TEST_CASE("VFuncSwap tests", "[VFuncSwap]") {
	std::shared_ptr<VirtualTest2> ClassToHook(new VirtualTest2);

	SECTION("Verify vfunc redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams2}};
		PLH::VFuncSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs2);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs2.size() == 1);

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify multiple vfunc redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)hkVirtNoParams2},{(uint16_t)2, (uint64_t)hkVirt2NoParams2}};
		PLH::VFuncSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs2);
		REQUIRE(hook.hook());
		REQUIRE(origVFuncs2.size() == 2);

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());

		vFuncSwapEffects.PushEffect();
		ClassToHook->NoParamVirt2();
		REQUIRE(vFuncSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}
}