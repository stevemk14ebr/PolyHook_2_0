//
// Created by steve on 3/22/17.
//
#include "../Catch.hpp"
#include "../src/CapstoneDisassembler.hpp"

std::vector<uint8_t> x64ASM = {
        //start address = 0x1800182B0
        0x48, 0x89, 0x5C, 0x24, 0x08,   //mov    QWORD PTR [rsp+0x8],rbx
        0x48, 0x89, 0x74, 0x24, 0x10,   //mov    QWORD PTR [rsp+0x10],rsi
        0x57,                           //push rdi
        0x48, 0x83, 0xEC, 0x20,         //sub rsp, 0x20
        0x49, 0x8B, 0xF8,               //mov rdi, r8
        0x8B, 0xDA,                     //mov ebx, edx
        0x48, 0x8B, 0xF1,               //mov rsi, rcx
        0x83, 0xFA, 0x01,               //cmp edx, 1
        0x75, 0xE4,                     //jne  0x1800182D1 when @0x1800182CA (base + 0x5 + 0x2)
        0xE8, 0xCB, 0x57, 0x01, 0x00    //call 0x18002DA9C when @0x1800182CC (base + 0x157CB + 0x5)
};

TEST_CASE("Test Capstone Disassembler","[ADisassembler],[CapstoneDisassembler]")
{
    PLH::CapstoneDisassembler disasm(PLH::ADisassembler::Mode::x64);

    auto Instructions =
            disasm.Disassemble(0x1800182B0, (uint64_t)&x64ASM.front(),
                               (uint64_t)&x64ASM.front() + x64ASM.size());

    printf("Instruction Count: %d\n",Instructions.size());
    for(auto const& Inst : Instructions)
    {
        printf("%"PRIx64"[%d]: ",Inst->GetAddress(),Inst->Size());
        for(int i = 0; i< Inst->Size(); i++)
            printf("%02X ",Inst->GetByte(i));
        printf("%s\n",Inst->GetFullName().c_str());
    }
}

