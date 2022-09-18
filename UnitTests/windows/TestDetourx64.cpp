//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

#include <asmjit/asmjit.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

EffectTracker effects;

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

NOINLINE void hookMe1() {
    PLH::StackCanary canary;
    volatile int var = 1;
    volatile int var2 = 0;
    var2 += 3;
    var2 = var + var2;
    var2 *= 30 / 3;
    var = 2;
    printf("%d %d\n", var, var2); // 2, 40
    REQUIRE(var == 2);
    REQUIRE(var2 == 40);
}

uint64_t hookMe1Tramp = NULL;
HOOK_CALLBACK(&hookMe1, h_hookMe1, {
    PLH::StackCanary canary;
    std::cout << "Hook 1 Called!" << std::endl;
    effects.PeakEffect().trigger();
    return PLH::FnCast(hookMe1Tramp, &hookMe1)();
});

NOINLINE void hookMe2() {
    PLH::StackCanary canary;
    for (int i = 0; i < 10; i++) {
        printf("%d\n", i);
    }
}

uint64_t hookMe2Tramp = NULL;
HOOK_CALLBACK(&hookMe2, h_hookMe2, {
    PLH::StackCanary canary;
    std::cout << "Hook 2 Called!" << std::endl;
    effects.PeakEffect().trigger();
    return PLH::FnCast(hookMe2Tramp, &hookMe2)();
});

unsigned char hookMe3[] = {
    0x57, // push rdi
    0x74, 0xf9,
    0x74, 0xf0,//je 0x0
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0xc3
};

unsigned char hookMe4[] = {
    0x57, // push rdi
    0x48, 0x83, 0xec, 0x30, //sub rsp, 0x30
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,
    0x74, 0xf2, //je 0x0
    0xc3
};

// test call instructions in prologue
unsigned char hookMe5[] =
{
    0x48, 0x83, 0xEC, 0x28, // 180009240: sub rsp, 28h
    0xE8, 0x96, 0xA8, 0xFF, 0xFF, // call 180003ADF
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 28h
    0x48, 0xFF, 0xA0, 0x20, 0x01, 0x00, 0x00 // jmp qword ptr[rax+120h]
};

// old NtQueueApcThread, call fs:0xC0 was weird
unsigned char hookMe6[] =
{
    0xb8, 0x44, 0x00, 0x00, 0x00, // mov eax, 0x44
    0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00, // call large dword ptr fs:0xc0
    0xc2, 0x14, 0x00 // retn 0x14
};

uint64_t nullTramp = NULL;

NOINLINE void h_nullstub() {
    PLH::StackCanary canary;
    volatile int i = 0;
    PH_UNUSED(i);
}

uint64_t hookMallocTramp = NULL;
HOOK_CALLBACK(&malloc, h_hookMalloc, { // NOLINT(cert-err58-cpp)
    PLH::StackCanary canary;
    volatile int i = 0;
    PH_UNUSED(i);
    effects.PeakEffect().trigger();

    return PLH::FnCast(hookMallocTramp, &malloc)(_args...);
});

uint64_t oCreateMutexExA = 0;
HOOK_CALLBACK(&CreateMutexExA, hCreateMutexExA, { // NOLINT(cert-err58-cpp)
    PLH::StackCanary canary;
    LPCSTR lpName = GET_ARG(1);
    printf("kernel32!CreateMutexExA  Name:%s\n", lpName);
    return PLH::FnCast(oCreateMutexExA, &CreateMutexExA)(_args...);
});

typedef void(*PKNORMAL_ROUTINE)(void* NormalContext, void* SystemArgument1, void* SystemArgument2);
typedef unsigned long(__stdcall* tNtQueueApcThread)(void* ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, void* NormalContext, void* SystemArgument1, void* SystemArgument2);

uint64_t hkNtQueueapcThread = NULL;
tNtQueueApcThread pNtQueueApcthread = (tNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
HOOK_CALLBACK(pNtQueueApcthread, h_NtQueueapcThread, { // NOLINT(cert-err58-cpp)
    std::cout << "hkNtQueueApcThread!" << std::endl;

    return PLH::FnCast(hkNtQueueapcThread, pNtQueueApcthread)(_args...);
});

TEST_CASE("Testing x64 detours", "[x64Detour][ADetour]") {
    SECTION("Normal function") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe1, (uint64_t) h_hookMe1, &hookMe1Tramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        hookMe1();
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Normal function rehook")
    {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe1, (uint64_t) h_hookMe1, &hookMe1Tramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        REQUIRE(detour.reHook() == true); // can only really test this doesn't cause memory corruption easily
        hookMe1();
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

        // In release mode win apis usually go through two levels of jmps
        /*
        0xe9 ... jmp iat_thunk

        iat_thunk:
        0xff 25 ... jmp [api_implementation]

        api_implementation:
            sub rsp, ...
            ... the goods ...
        */
    SECTION("WinApi Indirection") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &CreateMutexExA, (uint64_t) hCreateMutexExA, &oCreateMutexExA);
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Loop function") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe2, (uint64_t) h_hookMe2, &hookMe2Tramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        hookMe2();
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Jmp into prol w/src in range") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe3, (uint64_t) &h_nullstub, &nullTramp);
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Jmp into prol w/src out of range") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe4, (uint64_t) &h_nullstub, &nullTramp);

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Call instruction early in prologue") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &hookMe5, (uint64_t) &h_nullstub, &nullTramp);

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Call with fs base") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t)&hookMe6, (uint64_t)&h_nullstub, &nullTramp);

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("hook malloc") {
        PLH::StackCanary canary;
        PLH::x64Detour detour((uint64_t) &malloc, (uint64_t) h_hookMalloc, &hookMallocTramp);
        effects.PushEffect(); // catch does some allocations, push effect first so peak works

        REQUIRE(detour.hook());

        void* pMem = malloc(16);
        free(pMem);
        detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
        REQUIRE(effects.PopEffect().didExecute());
    }

    SECTION("queue apc thread") {
        PLH::x64Detour detour((uint64_t)pNtQueueApcthread, (uint64_t)h_NtQueueapcThread, &hkNtQueueapcThread);
        effects.PushEffect(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);
    }
}
