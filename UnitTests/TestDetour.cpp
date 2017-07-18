//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "headers/Detour/ADetour.hpp"

int hookMe() {
    std::cout << "Hook Me says hi" << std::endl;
    return 0;
}
decltype(&hookMe) oHookMe;

int hookMeCallback() {
    std::cout << "Callback says hi first" << std::endl;
    return oHookMe();
}

TEST_CASE("Testing x86 detours", "[ADetour]") {
    PLH::Detour<PLH::x64DetourImp> detour((char*)&hookMe, (char*)&hookMeCallback);
    detour.setDebug(true);

    REQUIRE(detour.Hook() == true);

    oHookMe = detour.getOriginal<decltype(&hookMe)>();

    hookMe();
}
