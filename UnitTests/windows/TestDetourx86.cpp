//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "polyhook2/Detour/x86Detour.hpp"

#include "polyhook2/Tests/TestEffectTracker.hpp"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

EffectTracker effects;

NOINLINE int __cdecl hookMe1() {
    volatile int var = 1;
    volatile int var2 = 0;
    var2 += 3;
    var2 = var + var2;
    var2 *= 30 / 3;
    var = 2;
    printf("%d %d\n", var, var2); // 2, 40
    return var;
}

uint64_t hookMe1Tramp = NULL;
HOOK_CALLBACK(&hookMe1, h_hookMe1, { // NOLINT(cert-err58-cpp)
    std::cout << "Hook 1 Called!" << std::endl;

    effects.PeakEffect().trigger();
    return PLH::FnCast(hookMe1Tramp, &hookMe1)();
});

typedef void(*PKNORMAL_ROUTINE)(void* NormalContext, void* SystemArgument1,void* SystemArgument2);
typedef unsigned long(__stdcall* tNtQueueApcThread)(void* ThreadHandle,PKNORMAL_ROUTINE ApcRoutine,void* NormalContext,void* SystemArgument1,void* SystemArgument2);

uint64_t hkNtQueueapcThread = NULL;
tNtQueueApcThread pNtQueueApcthread = (tNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
HOOK_CALLBACK(pNtQueueApcthread, h_NtQueueapcThread, { // NOLINT(cert-err58-cpp)
    std::cout << "hkNtQueueApcThread!" << std::endl;

    return PLH::FnCast(hkNtQueueapcThread, pNtQueueApcthread)(_args...);
});

/*  55                      push   ebp
1:  8b ec                   mov    ebp,esp
3:  74 fb                   je     0x0
5:  74 fa                   je     0x1
7:  8b ec                   mov    ebp,esp
9:  8b ec                   mov    ebp,esp
b:  8b ec                   mov    ebp,esp
d:  90                      nop
e:  90                      nop
f:  90                      nop
10: 90                      nop
11: 90                      nop */
unsigned char hookMe2[] = {0x55, 0x8b, 0xec, 0x74, 0xFB, 0x74, 0xea, 0x74, 0xFA, 0x8b, 0xec, 0x8b, 0xec, 0x8b, 0xec,
                           0x90, 0x90, 0x90, 0x90, 0x90};
uint64_t nullTramp = NULL;

NOINLINE void __cdecl h_nullstub() {
    volatile int i = 0;
    PH_UNUSED(i);
}

/*
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  89 e5                   mov    ebp,esp
5:  89 e5                   mov    ebp,esp
7:  89 e5                   mov    ebp,esp
9:  90                      nop
a:  90                      nop
b:  7f f4                   jg     0x1
*/
unsigned char hookMe3[] = {0x55, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x89, 0xE5, 0x90, 0x90, 0x7F, 0xF4};


uint8_t hookMe4[] = {
    0x55,                   // push ebp
    0x8B, 0xEC,             // mov ebp, esp
    0x56,                   // push esi
    0x8B, 0x75, 0x08,       // mov esi, [ebp+8]
    0xF6, 0x46, 0x30, 0x02, // test byte ptr ds:[esi+0x30], 0x2
    0xC3                    // ret
};

// old NtQueueApcThread, call fs:0xC0 was weird
unsigned char hookMe5[] =
{
    0xb8, 0x44, 0x00, 0x00, 0x00, // mov eax, 0x44
    0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00, // call dword ptr fs:0xc0
    0xc2, 0x14, 0x00 // retn 0x14
};

NOINLINE void PH_ATTR_NAKED hookMeLoop() {
#ifdef _MSC_VER
    __asm {
        xor eax, eax
        start :
        inc eax
        cmp eax, 5
        jle start
        ret
    }
#elif __GNUC__
    asm(
        "xor %eax, %eax;\n\t"
        "START: inc %eax;\n\t"
        "cmp $5, %eax;\n\t"
        "jle START;\n\t"
        "ret;"
    );
#else
#error "Please implement this for your compiler!"
#endif
}

uint64_t hookMeLoopTramp = NULL;
HOOK_CALLBACK(&hookMeLoop, h_hookMeLoop, { // NOLINT(cert-err58-cpp)
    std::cout << "Hook loop Called!" << std::endl;

    effects.PeakEffect().trigger();
    PLH::FnCast(hookMeLoopTramp, &hookMeLoop)();
});

#include <cstdarg>

uint64_t hookPrintfTramp = NULL;

NOINLINE int __cdecl h_hookPrintf(const char* format, ...) {
    char buffer[512];
    va_list args;
        va_start(args, format);
    vsprintf_s(buffer, format, args);
        va_end(args);

    effects.PeakEffect().trigger();
    return PLH::FnCast(hookPrintfTramp, &printf)("INTERCEPTED YO:%s", buffer);
}

//#include <cmath>

// must specify specific overload of std::pow by assiging to pFn of type
double (* pFnPowDouble)(double, double) = &std::pow;

uint64_t hookPowTramp = NULL;
HOOK_CALLBACK(pFnPowDouble, h_hookPow, { // NOLINT(cert-err58-cpp)
    effects.PeakEffect().trigger();
    return PLH::FnCast(hookPowTramp, pFnPowDouble)(_args...);
});

#include <cstdlib>

uint64_t hookMallocTramp = NULL;
HOOK_CALLBACK(&malloc, h_hookMalloc, { // NOLINT(cert-err58-cpp)
    effects.PeakEffect().trigger();
    return PLH::FnCast(hookMallocTramp, &malloc)(_args...);
});

#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")

uint64_t hookRecvTramp = NULL;
HOOK_CALLBACK(&recv, h_hookRecv, { // NOLINT(cert-err58-cpp)
    return PLH::FnCast(hookRecvTramp, &recv)(_args...);
});

TEST_CASE("Testing x86 detours", "[x86Detour][ADetour]") {
    SECTION("Normal function") {
        PLH::x86Detour detour((uint64_t) &hookMe1, (uint64_t) h_hookMe1, &hookMe1Tramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        volatile auto result = hookMe1();
        PH_UNUSED(result);
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Normal function rehook") {
        PLH::x86Detour detour((uint64_t) &hookMe1, (uint64_t) h_hookMe1, &hookMe1Tramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        REQUIRE(detour.reHook() == true); // can only really test this doesn't cause memory corruption easily
        volatile auto result = hookMe1();
        PH_UNUSED(result);
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Jmp into prologue w/ src in range") {
        PLH::x86Detour detour((uint64_t) &hookMe2, (uint64_t) &h_nullstub, &nullTramp);

        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Jmp into prologue w/ src out of range") {
        PLH::x86Detour detour((uint64_t) &hookMe3, (uint64_t) &h_nullstub, &nullTramp);
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }
    
    SECTION("Test instruction in prologue") {
        PLH::x86Detour detour((uint64_t) &hookMe4, (uint64_t) &h_nullstub, &nullTramp);
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Call with fs base") {
        PLH::x86Detour detour((uint64_t)&hookMe5, (uint64_t)&h_nullstub, &nullTramp);
        REQUIRE(detour.hook() == true);
        REQUIRE(detour.unHook() == true);
    }

    SECTION("Loop") {
        PLH::x86Detour detour((uint64_t) &hookMeLoop, (uint64_t) h_hookMeLoop, &hookMeLoopTramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        hookMeLoop();
        REQUIRE(effects.PopEffect().didExecute());
        REQUIRE(detour.unHook() == true);
    }

    SECTION("hook printf") {
        PLH::x86Detour detour((uint64_t) &printf, (uint64_t) h_hookPrintf, &hookPrintfTramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        printf("%s %f\n", "hi", .5f);
        detour.unHook();
        REQUIRE(effects.PopEffect().didExecute());
    }

        // it's a pun...
    SECTION("hook pow") {
        PLH::x86Detour detour((uint64_t) pFnPowDouble, (uint64_t) h_hookPow, &hookPowTramp);
        REQUIRE(detour.hook() == true);

        effects.PushEffect();
        volatile double result = pFnPowDouble(2, 2);
        PH_UNUSED(result);
        detour.unHook();
        REQUIRE(effects.PopEffect().didExecute());
    }

    SECTION("hook malloc") {
        PLH::x86Detour detour((uint64_t) &malloc, (uint64_t) h_hookMalloc, &hookMallocTramp);
        effects.PushEffect(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);

        void* pMem = malloc(16);
        free(pMem);
        detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
        REQUIRE(effects.PopEffect().didExecute());
    }

    SECTION("hook recv") {
        PLH::x86Detour detour((uint64_t) &recv, (uint64_t)h_hookRecv, &hookRecvTramp);
        REQUIRE(detour.hook() == true);
    }

    SECTION("queue apc thread") {
        PLH::x86Detour detour((uint64_t)pNtQueueApcthread, (uint64_t)h_NtQueueapcThread, &hkNtQueueapcThread);
        effects.PushEffect(); // catch does some allocations, push effect first so peak works
        REQUIRE(detour.hook() == true);
    }
}
