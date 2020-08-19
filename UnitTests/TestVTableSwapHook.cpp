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

typedef int(__stdcall* tVirtNoParams)(uintptr_t pThis);
PLH::VFuncMap origVFuncs;

NOINLINE int __stdcall hkVirtNoParams(uintptr_t pThis) {
	vTblSwapEffects.PeakEffect().trigger();
	return ((tVirtNoParams)origVFuncs.at(1))(pThis);
}

NOINLINE int __stdcall hkVirt2NoParams(uintptr_t pThis) {
	vTblSwapEffects.PeakEffect().trigger();
	return ((tVirtNoParams)origVFuncs.at(2))(pThis);
}

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);

	SECTION("Verify vtable redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)&hkVirtNoParams}};
		PLH::VTableSwapHook hook((char*)ClassToHook.get(), redirect);
		REQUIRE(hook.hook());
		origVFuncs = hook.getOriginals();
		REQUIRE(origVFuncs.size() == 1);

		vTblSwapEffects.PushEffect();
		ClassToHook->NoParamVirt();
		REQUIRE(vTblSwapEffects.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify multiple vtable redirected") {
		PLH::StackCanary canary;
		PLH::VFuncMap redirect = {{(uint16_t)1, (uint64_t)&hkVirtNoParams},{(uint16_t)2, (uint64_t)&hkVirtNoParams}};
		PLH::VTableSwapHook hook((char*)ClassToHook.get(), redirect);
		REQUIRE(hook.hook());
		origVFuncs = hook.getOriginals();
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