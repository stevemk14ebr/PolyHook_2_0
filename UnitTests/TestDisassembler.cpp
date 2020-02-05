//
// Created by steve on 3/22/17.
//
#include "Catch.hpp"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/ZydisDisassembler.hpp"

#include <iostream>
#include <vector>
#include <random>
std::vector<uint8_t> x64ASM = {
	//start address = 0x1800182B0
	0x48, 0x89, 0x5C, 0x24, 0x08,           //0) mov QWORD PTR [rsp+0x8],rbx    with child @index 8
	0x48, 0x89, 0x74, 0x24, 0x10,           //1) mov QWORD PTR [rsp+0x10],rsi
	0x57,                                   //2) push rdi
	0x48, 0x83, 0xEC, 0x20,                 //3) sub rsp, 0x20
	0x49, 0x8B, 0xF8,                       //4) mov rdi, r8
	0x8B, 0xDA,                             //5) mov ebx, edx
	0x48, 0x8B, 0xF1,                       //6) mov rsi, rcx
	0x83, 0xFA, 0x01,                       //7) cmp edx, 1
	0x75, 0xE4,                             //8) jne  0x1800182B0   when @0x1800182CA (base + 0xE4(neg) + 0x2)
	0xE8, 0xCB, 0x57, 0x01, 0x00,           //9) call 0x18002DA9C   when @0x1800182CC (base + 0x157CB + 0x5)
	0xFF, 0x25, 0xCB, 0x57, 0x01, 0x00,     //10)jmp qword ptr [rip + 0x157cb]  when @0x1800182d1FF
};

// page 590 for jmp types, page 40 for mod/rm table:
// https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
// stolen from capstones unit tests
std::vector<uint8_t> x86ASM = {
	//start @0x57b8edb8
	0x01, 0xc0,                         //0) 57b8edb8 add eax, eax
	0x81, 0xc6, 0x34, 0x12, 0x00, 0x00, //1) 57b8edba add esi, 0x1234
	0x05, 0x78, 0x56, 0x00, 0x00,       //2) 57b8edc0 add eax, 0x5678
	0x0f, 0x85, 0x08, 0x00, 0x00, 0x00, //3) 57b8edc5 jne 0x57b8edd3       child@6
	0x74, 0x00,                         //4) 57b8edcb je  0x57b8edcd
	0x8d, 0x87, 0x89, 0x67, 0x00, 0x00, //5) 57b8edcd lea eax, [edi+0x6789]child@4
	0xeb, 0xf0,                         //6) 57b8edd3 jmp 0x57b8edc5       child@3
	0xe9, 0x00, 0xff, 0x00, 0x00,        //7) 57b8edd5 jmp 57b9ecda
};

std::string filterJXX(const std::string& lhs) {
	if(lhs == "jnz")
		return "jne";
	else if(lhs == "jz")
		return "je";
	return lhs;
}

uint8_t randByte() {
	static std::random_device dev;
	static std::mt19937 rng(dev());
	static std::uniform_int_distribution<int> gen(0, 255);
	return (uint8_t)gen(rng);
}

TEST_CASE("Test Instruction UUID generator", "[Instruction],[UID]") {
	PLH::Instruction::Displacement displacement;
	displacement.Absolute = 0;

	long lastID = 0;
	for (int i = 0; i < 30; i++) {
		auto inst = PLH::Instruction(0,
									 displacement,
									 0,
									 false,
									 {},
									 0,
									 "nothing",
									 "nothing", PLH::Mode::x86);

		auto instCopy = inst;
		REQUIRE(instCopy.getUID() == inst.getUID());

		if (i != 0)
			REQUIRE(inst.getUID() != lastID);
		lastID = inst.getUID();
	}
}

TEMPLATE_TEST_CASE("Test Disassemblers x64", "[ADisassembler],[CapstoneDisassembler],[ZydisDisassembler]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	TestType disasm(PLH::Mode::x64);
	auto                      Instructions = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
		(uint64_t)&x64ASM.front() + x64ASM.size());

	uint64_t PrevInstAddress = (uint64_t)&x64ASM.front();
	size_t   PrevInstSize = 0;

	const char* CorrectMnemonic[] = {"mov", "mov", "push", "sub", "mov", "mov", "mov", "cmp", "jne", "call", "jmp"};
	const uint8_t CorrectSizes[] = {5, 5, 1, 4, 3, 2, 3, 3, 2, 5, 6};

	SECTION("Check disassembler integrity") {
		REQUIRE(Instructions.size() == 11);

		std::cout << Instructions << std::endl;

		for (const auto &p : disasm.getBranchMap()) {
			std::cout << std::hex << "dest: " << p.first << " " << std::dec << p.second << std::endl;
		}
	}

	SECTION("Check branch map") {
		auto brMap = disasm.getBranchMap();
		REQUIRE(brMap.size() == 1);
		REQUIRE(brMap.find(Instructions[0].getAddress()) != brMap.end());
	}

	SECTION("Check instruction re-encoding integrity") {
		auto vecCopy = x64ASM;
		Instructions[8].setRelativeDisplacement(0x00);
		disasm.writeEncoding(Instructions[8]);

		Instructions[9].setRelativeDisplacement(0x00);
		disasm.writeEncoding(Instructions[9]);

		REQUIRE(Instructions[8].getDestination() == Instructions[8].getAddress() + Instructions[8].size());
		REQUIRE(Instructions[9].getDestination() == Instructions[9].getAddress() + Instructions[9].size());

		// undo writes
		x64ASM = vecCopy;
		Instructions = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
			(uint64_t)&x64ASM.front() + x64ASM.size());
	}

	for (size_t i = 0; i < Instructions.size(); i++) {
		INFO("Index: " << i
			 << " Correct Mnemonic:"
			 << CorrectMnemonic[i]
			 << " Mnemonic:"
			 << filterJXX(Instructions[i].getMnemonic()));

		REQUIRE(filterJXX(Instructions[i].getMnemonic()).compare(CorrectMnemonic[i]) == 0);

		REQUIRE(Instructions[i].size() == CorrectSizes[i]);

		REQUIRE(Instructions[i].getAddress() == (PrevInstAddress + PrevInstSize));
		PrevInstAddress = Instructions[i].getAddress();
		PrevInstSize = Instructions[i].size();
	}

	SECTION("Check multiple calls") {
		PLH::insts_t insts;
		for (int i = 0; i < 100; i++) {
			insts = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
				(uint64_t)&x64ASM.front() + x64ASM.size());
		}
	}

	SECTION("Verify branching, relative fields") {
		PLH::insts_t insts = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
			(uint64_t)&x64ASM.front() + x64ASM.size());

		REQUIRE(insts.at(0).hasDisplacement() == false);
		REQUIRE(insts.at(0).isBranching() == false);

		REQUIRE(insts.at(1).hasDisplacement() == false);
		REQUIRE(insts.at(1).isBranching() == false);

		REQUIRE(insts.at(8).hasDisplacement());
		REQUIRE(insts.at(8).isBranching());

		REQUIRE(insts.at(9).hasDisplacement());
		REQUIRE(insts.at(9).isBranching());

		REQUIRE(insts.at(10).isBranching());
		REQUIRE(insts.at(10).hasDisplacement());
	}

	SECTION("Test garbage instructions") {
		char randomBuf[500];
		for (int i = 0; i < 500; i++)
			randomBuf[i] = randByte();

		auto insts = disasm.disassemble((uint64_t)randomBuf, (uint64_t)0x0,
										500);
		std::cout << insts << std::endl;
	}
}

TEMPLATE_TEST_CASE("Test Disassemblers x86", "[ADisassembler],[CapstoneDisassembler],[ZydisDisassembler]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	TestType disasm(PLH::Mode::x86);
	auto                      Instructions = disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
		(uint64_t)&x86ASM.front() + x86ASM.size());

	const uint8_t CorrectSizes[] = {2, 6, 5, 6, 2, 6, 2, 5};
	const char* CorrectMnemonic[] = {"add", "add", "add", "jne", "je", "lea", "jmp", "jmp"};

	SECTION("Check disassembler integrity") {
		REQUIRE(Instructions.size() == 8);
		std::cout << Instructions << std::endl;

		for (const auto &p : disasm.getBranchMap()) {
			std::cout << std::hex << "dest: " << p.first << " -> " << std::dec << p.second << std::endl;
		}
	}

	SECTION("Check branch map") {
		auto brMap = disasm.getBranchMap();
		REQUIRE(brMap.size() == 3);
		REQUIRE(brMap.find(Instructions[3].getAddress()) != brMap.end());
		REQUIRE(brMap.find(Instructions[5].getAddress()) != brMap.end());
		REQUIRE(brMap.find(Instructions[6].getAddress()) != brMap.end());
	}

	SECTION("Check instruction re-encoding integrity") {
		auto vecCopy = x86ASM;
		Instructions[3].setRelativeDisplacement(0x00);
		disasm.writeEncoding(Instructions[3]);

		Instructions[6].setRelativeDisplacement(0x00);
		disasm.writeEncoding(Instructions[6]);

		REQUIRE(Instructions[3].getDestination() == Instructions[3].getAddress() + Instructions[3].size());
		REQUIRE(Instructions[6].getDestination() == Instructions[6].getAddress() + Instructions[6].size());

		// undo writes
		x86ASM = vecCopy;
		Instructions =
			disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
			(uint64_t)&x86ASM.front() + x86ASM.size());
	}

	uint64_t PrevInstAddress = (uint64_t)&x86ASM.front();
	size_t   PrevInstSize = 0;


	for (size_t i = 0; i < Instructions.size(); i++) {
		INFO("Index: " << i);
		INFO("Correct Mnemonic:"
			 << CorrectMnemonic[i]
			 << " Mnemonic:"
			 << Instructions[i].getMnemonic());

		REQUIRE(filterJXX(Instructions[i].getMnemonic()).compare(CorrectMnemonic[i]) == 0);

		REQUIRE(Instructions[i].size() == CorrectSizes[i]);

		REQUIRE(Instructions[i].getAddress() == (PrevInstAddress + PrevInstSize));
		PrevInstAddress = Instructions[i].getAddress();
		PrevInstSize = Instructions[i].size();
	}
	REQUIRE(Instructions.size() == 8);

	SECTION("Check multiple calls") {
		PLH::insts_t insts;
		for (int i = 0; i < 100; i++) {
			insts = disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
				(uint64_t)&x86ASM.front() + x86ASM.size());
		}
	}

	SECTION("Verify branching, relative fields") {
		PLH::insts_t insts = disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
			(uint64_t)&x86ASM.front() + x86ASM.size());

		REQUIRE(insts.at(4).isBranching());
		REQUIRE(insts.at(4).hasDisplacement());

		REQUIRE(insts.at(5).isBranching() == false);
		REQUIRE(insts.at(5).hasDisplacement() == false);

		REQUIRE(insts.at(6).isBranching());
		REQUIRE(insts.at(6).hasDisplacement());

		REQUIRE(insts.at(7).isBranching());
		REQUIRE(insts.at(7).hasDisplacement());
	}

	SECTION("Test garbage instructions") {
		char randomBuf[500];
		for (int i = 0; i < 500; i++)
			randomBuf[i] = randByte();

		auto insts = disasm.disassemble((uint64_t)randomBuf, (uint64_t)0x0,
										500);
		std::cout << insts << std::endl;
	}
}

TEST_CASE("Compare x86 Decompilers", "[ADisassembler],[ZydisDisassembler][CapstoneDisassembler]") {
	// Use capstone as reference
	PLH::CapstoneDisassembler disasmRef(PLH::Mode::x86);
	auto                      InstructionsRef = disasmRef.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
		(uint64_t)&x86ASM.front() + x86ASM.size());

	PLH::ZydisDisassembler disasm(PLH::Mode::x86);
	auto                      Instructions = disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
		(uint64_t)&x86ASM.front() + x86ASM.size());

	SECTION("Check Integrity") {
		REQUIRE(Instructions.size() == 8);
		std::cout << Instructions << std::endl;

		for (const auto &p : disasm.getBranchMap()) {
			std::cout << std::hex << "dest: " << p.first << " -> " << std::dec << p.second << std::endl;
		}

		for (size_t i = 0; i < Instructions.size(); i++) {
			INFO("Index: " << i << " Mnemonic:"
			<< Instructions[i].getMnemonic());

			REQUIRE(filterJXX(Instructions[i].getMnemonic()) == filterJXX(InstructionsRef[i].getMnemonic()));
			REQUIRE(Instructions[i].size() == InstructionsRef[i].size());
			REQUIRE(Instructions[i].isBranching() == InstructionsRef[i].isBranching());

			REQUIRE(Instructions[i].getAddress() == InstructionsRef[i].getAddress());
			REQUIRE(Instructions[i].getDestination() == InstructionsRef[i].getDestination());
		}
	}
}
