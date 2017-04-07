//
// Created by steve on 3/22/17.
//
#include "../Catch.hpp"
#include "../src/CapstoneDisassembler.hpp"

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
        0x75, 0xE4,                             //8) jne  0x1800182B0               when @0x1800182CA (base + 0xE4(neg) + 0x2)
        0xE8, 0xCB, 0x57, 0x01, 0x00,           //9) call 0x18002DA9C               when @0x1800182CC (base + 0x157CB + 0x5)
        0xFF, 0x25, 0xCB, 0x57, 0x01, 0x00,     //10)jmp qword ptr [rip + 0x157cb]  when @0x1800182d1FF
};

TEST_CASE("Test Capstone Disassembler","[ADisassembler],[CapstoneDisassembler]")
{
    PLH::CapstoneDisassembler disasm(PLH::ADisassembler::Mode::x64);
    auto Instructions =
            disasm.Disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
                               (uint64_t)&x64ASM.front() + x64ASM.size());

    //TO-DO: Break this section in further sub-sections
    SECTION("Check disassembler integrity")
    {
        REQUIRE(Instructions.size() == 11);
        const uint8_t CorrectSizes[] = {5,5,1,4,3,2,3,3,2,5,6};

        const char* CorrectMnemonic[] = {"mov","mov","push","sub","mov","mov","mov","cmp","jne","call","jmp" };
        const bool CorrectChildCount[] = {1,0,0,0,0,0,0,0,0,0,0};
        const std::vector<std::shared_ptr<PLH::Instruction>> CorrectChildren[] = {{Instructions[8]}}; //array of vectors

        uint64_t PrevInstAddress = (uint64_t)&x64ASM.front();
        size_t PrevInstSize = 0;
        for(int i = 0; i < Instructions.size();i++)
        {
            INFO("Index: " << i);
            REQUIRE(Instructions[i]->Size() == CorrectSizes[i]);

            INFO("Index: " << i);
            REQUIRE(Instructions[i]->GetAddress() == (PrevInstAddress + PrevInstSize));
            PrevInstAddress = Instructions[i]->GetAddress();
            PrevInstSize = Instructions[i]->Size();

            INFO("Index: " << i << " Correct Mnemonic:" << CorrectMnemonic[i] << " Mnemonic:"<<Instructions[i]->GetMnemonic());
            REQUIRE(Instructions[i]->GetMnemonic().compare(CorrectMnemonic[i]) == 0);

            INFO("Index: " << i);
            auto Children = Instructions[i]->GetChildren();
            REQUIRE(Children.size() == CorrectChildCount[i]);
            if(Children.size() > 0)
            {
                for(int j = 0; j < Children.size();j++)
                {
                    INFO("Instruction Index:" << i << " Child Index:" << j);
                    REQUIRE(Instructions[i]->GetChildren().at(j) == CorrectChildren[i][j]);
                }
            }
        }
    }

    SECTION("Check instruction re-encoding integrity")
    {
        printf("\n-------------------\n");

        Instructions[8]->SetRelativeDisplacement(0x00);
        disasm.WriteEncoding(*Instructions[8]);

        Instructions[9]->SetRelativeDisplacement(0x00);
        disasm.WriteEncoding(*Instructions[9]);

        REQUIRE(Instructions[8]->GetDestination() == Instructions[8]->GetAddress() + Instructions[8]->Size());
        REQUIRE(Instructions[9]->GetDestination() == Instructions[9]->GetAddress() + Instructions[9]->Size());
        Instructions =
                disasm.Disassemble((uint64_t)&x64ASM.front(), (uint64_t)&x64ASM.front(),
                                   (uint64_t)&x64ASM.front() + x64ASM.size());
    }

    for(auto const& Inst : Instructions)
    {
        printf("Children[%ld] [%"PRIx64"] ",Inst->GetChildren().size(),Inst->GetAddress());
        for(int i = 0; i< Inst->Size(); i++)
            printf("%02X ",Inst->GetByte(i));
        printf("%s\n",Inst->GetFullName().c_str());
    }
}

