#include <dlfcn.h>
#include <gnu/lib-names.h>

#include <Catch.hpp>

#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"
#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "../TestUtils.hpp"

namespace {
	EffectTracker effects;
}

// TODO: Translation + INPLACE scheme

PLH_TEST_DETOUR_CALLBACK(dlmopen, {
	printf("Hooked dlmopen\n");
});

TEST_CASE("Testing Detours with Translations", "[Translation][ADetour]") {
	PLH::test::registerTestLogger();

	SECTION("dlmopen (INPLACE)") {
		PLH::StackCanary canary;

		const auto *resultBefore = dlmopen(LM_ID_BASE, LIBM_SO, RTLD_NOW);

		PLH::x64Detour detour((uint64_t)dlmopen, (uint64_t)dlmopen_hooked, &dlmopen_trmp);
		// Only INPLACE creates conditions for translation, since
		// trampoline will be close to 0x0, where as
		// dlmopen    will be close to 0x00007F__________
		detour.setDetourScheme(PLH::x64Detour::detour_scheme_t::INPLACE);
		REQUIRE(detour.hook());

		effects.PushEffect();
		const auto *resultAfter = dlmopen(LM_ID_BASE, LIBM_SO, RTLD_NOW);

		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(resultAfter == resultBefore);

		REQUIRE(detour.unHook());
	}
}
