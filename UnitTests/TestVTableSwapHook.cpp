#include <memory>

#include <Catch.hpp>

#include "headers/Virtuals/VTableSwapHook.hpp"
#include "headers/Tests/TestEffectTracker.hpp"

EffectTracker vTblSwapEffects;

class VirtualTest {
public:
	virtual int NoParamVirt() {
		return 4;
	}

	virtual int NoParamVirt2() {
		return 7;
	}
};

#pragma warning(disable: 4100)

typedef int(__thiscall* tVirtNoParams)(uintptr_t pThis);
PLH::VFuncMap origVFuncs;

NOINLINE int __fastcall hkVirtNoParams(uintptr_t pThis, void* edxDEAD) {
	vTblSwapEffects.PeakEffect().trigger();
	return ((tVirtNoParams)origVFuncs.at(0))(pThis);
}

NOINLINE int __fastcall hkVirt2NoParams(uintptr_t pThis, void* edxDEAD) {
	vTblSwapEffects.PeakEffect().trigger();
	return ((tVirtNoParams)origVFuncs.at(1))(pThis);
}

TEST_CASE("VTableSwap tests", "[VTableSwap]") {
	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);

	SECTION("Verify vtable redirected") {
		PLH::VFuncMap redirect = {{(uint16_t)0, (uint64_t)&hkVirtNoParams}};
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
		PLH::VFuncMap redirect = {{(uint16_t)0, (uint64_t)&hkVirtNoParams},{(uint16_t)1, (uint64_t)&hkVirtNoParams}};
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