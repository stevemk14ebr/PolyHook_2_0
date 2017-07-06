//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "headers/Detour/ADetour.hpp"

TEST_CASE("Testing x86 detours", "[ADetour]")
{
    PLH::Detour<PLH::x86DetourImp> detour((uint64_t)0,0);
}
