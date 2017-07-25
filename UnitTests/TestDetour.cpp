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

__attribute_noinline__ void prologueCycle() {
    bool cycled = false;
    cycle:
        if(!cycled) {
            cycled = true;
            goto cycle;
        }
}
decltype(&prologueCycle) oCycle;

__attribute_noinline__ void proCycleCallback(){
    return oCycle();
}

struct MemberFnClass
{
    void foo(){
        std::cout << "original foo" << std::endl;
    }

    int bar(int param)
    {
        std::cout << "original bar " << param << std::endl;
    }
};

MemberFnClass c;
typedef void(*tMemberFn)();
tMemberFn oMemberFn;

__attribute_noinline__ void fooCallback(){
    std::cout << "callback" << std::endl;
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

//    SECTION("Another cycle check with goto"){
//        PLH::Detour<PLH::x64DetourImp> detour((char*)&prologueCycle, (char*)&proCycleCallback);
//
//        detour.setDebug(true);
//        REQUIRE(detour.hook() == true);
//        oCycle = detour.getOriginal<decltype(&prologueCycle)>();
//
//        //prologueCycle();
//    }

    SECTION("Verify member function pointer hooks work")
    {
        typedef PLH::proxy<int(MemberFnClass::*)(int), &MemberFnClass::bar> proxy;
        PLH::Detour<PLH::x64DetourImp> detour((char*)&proxy::call, (char*)&fooCallback);
        //detour.setDebug(true);

        REQUIRE(detour.hook() == true);

        proxy::call(c,1);
    }
}
