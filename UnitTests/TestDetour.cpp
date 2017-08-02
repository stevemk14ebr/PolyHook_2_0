//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include <functional>
#include "headers/Detour/ADetour.hpp"

__attribute_noinline__ int branch(int param) {
    if(param > 0)
        return 15;

    return param;
}
decltype(&branch) oBranch;

__attribute_noinline__ int branchCallback(int param) {
    return oBranch(param + 5);
}

__attribute_noinline__ int loop(int param) {
    int i = 0;
    while(i < param)
    {
        i++;
    }
    return i;
}
decltype(&loop) oLoop;

__attribute_noinline__ int loopCallback(int param) {
    return oLoop(10);
}

uint8_t toSmall[1] = {0xC3};

//bunch of nops then a jump back into the second nop. Then some nops at the end for jump table to go into
uint8_t prologueCyclicJump[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                 0xEB, 0xF3,
                                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

__attribute_noinline__ void prologueLoopCallback(){
    return;
}

TEST_CASE("Testing detours", "[ADetour]") {

    // On gcc in linux this also tests that the red-zone isn't touched
    SECTION("Verify jump table works for functions that branch") {
        PLH::Detour<PLH::x64DetourImp> detour((char*)&branch, (char*)&branchCallback);

        //detour.setDebug(true);
        REQUIRE(detour.hook() == true);
        oBranch = detour.getOriginal<decltype(&branch)>();

        REQUIRE(branch(-5) == 0);
        REQUIRE(branch(0) == 15);
    }

    /* This is not fully implemented. Cyclic jumps usually don't happen since we
     * took care to use the smallest jump type, but they are possible. We
     * should check*/
    SECTION("Verify functions with loop are resolved")
    {
        PLH::Detour<PLH::x64DetourImp> detour((char*)&loop, (char*)&loopCallback);

        //detour.setDebug(true);
        REQUIRE(detour.hook() == true);
        oLoop = detour.getOriginal<decltype(&loop)>();

        REQUIRE(loop(5) == 10);
    }

    SECTION("Make sure small functions fail"){
        PLH::Detour<PLH::x64DetourImp> detour((char*)&toSmall, (char*)&toSmall);

        //Should fail because function is to small
        REQUIRE(!detour.hook());
    }

    SECTION("Check functions that jump back into prologue"){
        PLH::Detour<PLH::x64DetourImp> detour((char*)&prologueCyclicJump, (char*)&prologueLoopCallback);

        detour.setDebug(true);
        detour.hook();
    }
}
