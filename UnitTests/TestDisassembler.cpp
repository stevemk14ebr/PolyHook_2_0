//
// Created by steve on 3/22/17.
//
#include "Catch.hpp"
#include "headers/CapstoneDisassembler.hpp"

#include <iostream>
#include <vector>

//std::vector<uint8_t> x64ASM = {
//        //start address = 0x1800182B0
//        0x48, 0x89, 0x5C, 0x24, 0x08,           //0) mov QWORD PTR [rsp+0x8],rbx    with child @index 8
//        0x48, 0x89, 0x74, 0x24, 0x10,           //1) mov QWORD PTR [rsp+0x10],rsi
//        0x57,                                   //2) push rdi
//        0x48, 0x83, 0xEC, 0x20,                 //3) sub rsp, 0x20
//        0x49, 0x8B, 0xF8,                       //4) mov rdi, r8
//        0x8B, 0xDA,                             //5) mov ebx, edx
//        0x48, 0x8B, 0xF1,                       //6) mov rsi, rcx
//        0x83, 0xFA, 0x01,                       //7) cmp edx, 1
//        0x75, 0xE4,                             //8) jne  0x1800182B0   when @0x1800182CA (base + 0xE4(neg) + 0x2)
//        0xE8, 0xCB, 0x57, 0x01, 0x00,           //9) call 0x18002DA9C   when @0x1800182CC (base + 0x157CB + 0x5)
//        0xFF, 0x25, 0xCB, 0x57, 0x01, 0x00,     //10)jmp qword ptr [rip + 0x157cb]  when @0x1800182d1FF
//};
//
//TEST_CASE("Test Capstone Disassembler x64", "[ADisassembler],[CapstoneDisassembler]") {
//    PLH::CapstoneDisassembler disasm(PLH::Mode::x64);
//    auto                      Instructions = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
//                                                                (uint64_t)&x64ASM.front() + x64ASM.size());
//
//    uint64_t PrevInstAddress = (uint64_t)&x64ASM.front();
//    size_t   PrevInstSize    = 0;
//
//    const char* CorrectMnemonic[] = {"mov", "mov", "push", "sub", "mov", "mov", "mov", "cmp", "jne", "call", "jmp"};
//    const uint8_t CorrectSizes[] = {5, 5, 1, 4, 3, 2, 3, 3, 2, 5, 6};
//
//    //TO-DO: Break this section in further sub-sections
//    SECTION("Check disassembler integrity") {
//        REQUIRE(Instructions.size() == 11);
//    }
//
//    SECTION("Check instruction re-encoding integrity") {
//        Instructions[8].setRelativeDisplacement(0x00);
//        disasm.writeEncoding(Instructions[8]);
//
//        Instructions[9].setRelativeDisplacement(0x00);
//        disasm.writeEncoding(Instructions[9]);
//
//        REQUIRE(Instructions[8].getDestination() == Instructions[8].getAddress() + Instructions[8].size());
//        REQUIRE(Instructions[9].getDestination() == Instructions[9].getAddress() + Instructions[9].size());
//        Instructions = disasm.disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
//                                   (uint64_t)&x64ASM.front() + x64ASM.size());
//    }
//
//    for (int i = 0; i < Instructions.size(); i++) {
//        INFO("Index: " << i
//                       << " Correct Mnemonic:"
//                       << CorrectMnemonic[i]
//                       << " Mnemonic:"
//                       << Instructions[i].getMnemonic());
//
//        REQUIRE(Instructions[i].getMnemonic().compare(CorrectMnemonic[i]) == 0);
//
//        REQUIRE(Instructions[i].size() == CorrectSizes[i]);
//
//        REQUIRE(Instructions[i].getAddress() == (PrevInstAddress + PrevInstSize));
//        PrevInstAddress = Instructions[i].getAddress();
//        PrevInstSize    = Instructions[i].size();
//    }
//}

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
        0xe9, 0x00, 0xff, 0x00, 0x00        //7) 57b8edd5 jmp 57b9ecda
};

TEST_CASE("Test Capstone Disassembler x86", "[ADisassembler],[CapstoneDisassembler]") {
    PLH::CapstoneDisassembler disasm(PLH::Mode::x86);
    auto                      Instructions = disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
                                                                (uint64_t)&x86ASM.front() + x86ASM.size());
   
    const uint8_t CorrectSizes[] = {2, 6, 5, 6, 2, 6, 2, 5};
    const char* CorrectMnemonic[] = {"add", "add", "add", "jne", "je", "lea", "jmp", "jmp"};

    SECTION("Check disassembler integrity") {
		REQUIRE(Instructions.size() == 8);
    }

    SECTION("Check instruction re-encoding integrity") {
        Instructions[3].setRelativeDisplacement(0x00);
        disasm.writeEncoding(Instructions[3]);

        Instructions[7].setRelativeDisplacement(0x00);
        disasm.writeEncoding(Instructions[7]);

        REQUIRE(Instructions[3].getDestination() == Instructions[3].getAddress() + Instructions[3].size());
        REQUIRE(Instructions[7].getDestination() == Instructions[7].getAddress() + Instructions[7].size());

        Instructions =
                disasm.disassemble((uint64_t)&x86ASM.front(), (uint64_t)&x86ASM.front(),
                                   (uint64_t)&x86ASM.front() + x86ASM.size());
    }

    uint64_t PrevInstAddress = (uint64_t)&x86ASM.front();
    size_t   PrevInstSize    = 0;

    for (int i = 0; i < Instructions.size(); i++) {
        INFO("Index: " << i);
        INFO("Correct Mnemonic:"
                     << CorrectMnemonic[i]
                     << " Mnemonic:"
                     << Instructions[i].getMnemonic());

        REQUIRE(Instructions[i].getMnemonic().compare(CorrectMnemonic[i]) == 0);

        REQUIRE(Instructions[i].size() == CorrectSizes[i]);

        REQUIRE(Instructions[i].getAddress() == (PrevInstAddress + PrevInstSize));
        PrevInstAddress = Instructions[i].getAddress();
        PrevInstSize    = Instructions[i].size();
    }

}

