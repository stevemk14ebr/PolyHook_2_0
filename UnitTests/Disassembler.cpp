//
// Created by steve on 3/22/17.
//
#include "../Catch.hpp"
#include "../src/CapstoneDisassembler.hpp"
TEST_CASE("Test Capstone Disassembler","[ADisasembler],[CapstoneDisassembler]")
{
    PLH::CapstoneDisassembler disasm(PLH::ADisassembler::Mode::x64);
}

