//
// Created by steve on 7/4/17.
//
#include <Catch.hpp>
#include "headers/Detour/x86Detour.hpp"
#include "headers/Detour/X64Detour.hpp"
#include "headers/CapstoneDisassembler.hpp"

void __cdecl hookMe1() {
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
}
//PLH::Trampoline& hookMe1Tramp;

void __cdecl h_hookMe1() {
	std::cout << "Hook 1 Called!" << std::endl;
	//return hookMe1Tramp.get<decltype(&hookMe1)>()();
}

/*push ebp
  mov ebp, esp
  je *back to push ebp*
  je *back to mov*/
unsigned char hookMe2[] = {0x55, 0x8b, 0xec, 0x74, 0xFB, 0x74, 0xFA, 0x8b, 0xec,0x8b, 0xec,0x8b, 0xec,0x90, 0x90, 0x90, 0x90, 0x90 };
void __cdecl h_nullstub() {
	volatile int i = 0;
}

TEST_CASE("Testing x86 detours", "[x86Detour],[ADetour]") {
	PLH::CapstoneDisassembler dis(PLH::Mode::x86);

	SECTION("Normal function") {
		PLH::x86Detour detour((char*)&hookMe1, (char*)&h_hookMe1, dis);
		//hookMe1Tramp = detour.getTrampoline();
		REQUIRE(detour.hook() == true);

		hookMe1();
	}

	SECTION("Jmp into prologue") {
		PLH::x86Detour detour((char*)&hookMe2, (char*)&h_nullstub, dis);
		//hookMe1Tramp = detour.getTrampoline();
		REQUIRE(detour.hook() == true);
	}
}
