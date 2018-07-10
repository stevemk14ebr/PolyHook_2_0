//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>
#include "headers/Detour/X64Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

void hookMe1() {
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
}
uint64_t hookMe1Tramp = NULL;

void h_hookMe1() {
	std::cout << "Hook 1 Called!" << std::endl;
	return ((decltype(&hookMe1))(hookMe1Tramp))();
}

TEST_CASE("Testing x86 detours", "[x86Detour],[ADetour]") {
	PLH::CapstoneDisassembler dis(PLH::Mode::x64);

	SECTION("Normal function") {
		PLH::x64Detour detour((char*)&hookMe1, (char*)&h_hookMe1, dis);
		REQUIRE(detour.hook() == true);
		hookMe1Tramp = detour.getTrampoline();

		hookMe1();
	}
}