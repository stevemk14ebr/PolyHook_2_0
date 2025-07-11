#include <Catch.hpp>
#include "polyhook2/Detour/x86HotpatchDetour.hpp"

#include "polyhook2/Tests/TestEffectTracker.hpp"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

EffectTracker effectsHotpatch;


#include <cstdlib>

uint64_t hotpatchHookMallocTramp = NULL;
HOOK_CALLBACK(&malloc, h_hotpatchHookMalloc, { // NOLINT(cert-err58-cpp)
    effectsHotpatch.PeakEffect().trigger();
    return PLH::FnCast(hotpatchHookMallocTramp, &malloc)(_args...);
    });

#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")

uint64_t hotpatchHookRecvTramp = NULL;
HOOK_CALLBACK(&recv, h_hotpatchHookRecv, { // NOLINT(cert-err58-cpp)
    return PLH::FnCast(hotpatchHookRecvTramp, &recv)(_args...);
    });

typedef void(*PKNORMAL_ROUTINE)(void* NormalContext, void* SystemArgument1, void* SystemArgument2);
typedef unsigned long(__stdcall* tNtQueueApcThread)(void* ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, void* NormalContext, void* SystemArgument1, void* SystemArgument2);

uint64_t hotpatchHkNtQueueapcThread = NULL;
tNtQueueApcThread pHotpatchNtQueueApcthread = (tNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
HOOK_CALLBACK(pHotpatchNtQueueApcthread, h_hotpatchNtQueueapcThread, { // NOLINT(cert-err58-cpp)
    std::cout << "hkNtQueueApcThread!" << std::endl;

    return PLH::FnCast(hotpatchHkNtQueueapcThread, pHotpatchNtQueueApcthread)(_args...);
    });

TEST_CASE("Testing x86 hotpatch detours", "[x86HotpatchDetour][ADetour]") {
    SECTION("hook malloc") {
        PLH::x86HotpatchDetour detour((uint64_t)&malloc, (uint64_t)h_hotpatchHookMalloc, &hotpatchHookMallocTramp);
        effectsHotpatch.PushEffect(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);

        void* pMem = malloc(16);
        free(pMem);
        bool unHookRet = detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
        REQUIRE(unHookRet == true);
        REQUIRE(effectsHotpatch.PopEffect().didExecute());
    }

    SECTION("hook recv") {
        PLH::x86HotpatchDetour detour((uint64_t)&recv, (uint64_t)h_hotpatchHookRecv, &hotpatchHookRecvTramp);
        REQUIRE(detour.hook() == true);
    }

    SECTION("queue apc thread should fail due to too narrow space") {
        PLH::x86HotpatchDetour detour((uint64_t)pHotpatchNtQueueApcthread, (uint64_t)h_hotpatchNtQueueapcThread, &hotpatchHkNtQueueapcThread);
        effectsHotpatch.PushEffect(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == false);  
    }
}
