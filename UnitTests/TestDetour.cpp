//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "headers/Detour/ADetour.hpp"

volatile int hookMe()
{
    std::cout << "Hook Me says hi" << std::endl;
    return 0;
}

volatile int hookMeCallback()
{
    std::cout << "Callback says hi first" << std::endl;
    return 1;
}

TEST_CASE("Testing x86 detours", "[ADetour]")
{
    PLH::Detour<PLH::x64DetourImp> detour((uint8_t*)&hookMe, (uint8_t*)&hookMeCallback);
    detour.setDebug(true);

    REQUIRE(detour.Hook() == true);

    hookMe();
}
