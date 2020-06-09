#include <Catch.hpp>
#include "polyhook2/PE/IatHook.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"
#include "polyhook2/Tests/StackCanary.hpp"

EffectTracker iatEffectTracker;

typedef DWORD(__stdcall* tGetCurrentThreadId)();
uint64_t oGetCurrentThreadID;

NOINLINE DWORD __stdcall hkGetCurrentThreadId() {
	iatEffectTracker.PeakEffect().trigger();
	return ((tGetCurrentThreadId)oGetCurrentThreadID)();
}

TEST_CASE("Iat Hook Tests", "[IatHook]") {
	SECTION("Verify api thunk is found and hooked") {
		PLH::StackCanary canary;
		volatile DWORD thrdId2 = GetCurrentThreadId();
		UNREFERENCED_PARAMETER(thrdId2);
		PLH::IatHook hook("kernel32.dll", "GetCurrentThreadId", (char*)&hkGetCurrentThreadId, (uint64_t*)&oGetCurrentThreadID, L"");
		REQUIRE(hook.hook());
		
		iatEffectTracker.PushEffect();
		REQUIRE(canary.isStackGood());
		volatile DWORD thrdId = GetCurrentThreadId();
		thrdId++;
		REQUIRE(iatEffectTracker.PopEffect().didExecute());
		REQUIRE(hook.unHook());
	}

	SECTION("Verify api thunk is found and hooked when module explicitly named") {
		PLH::StackCanary canary;
		PLH::IatHook hook("kernel32.dll", "GetCurrentThreadId", (char*)&hkGetCurrentThreadId, (uint64_t*)&oGetCurrentThreadID, L"polyhook_2.exe");
		REQUIRE(hook.hook());

		iatEffectTracker.PushEffect();
		volatile DWORD thrdId = GetCurrentThreadId();
		thrdId++;
		REQUIRE(hook.unHook());
	}
}