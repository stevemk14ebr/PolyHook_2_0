//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Instruction.hpp"

PLH::Maybe<PLH::x64DetourImp::DetourBuffer> PLH::x64DetourImp::AllocateMemory(const uint64_t Hint) {
    uint64_t MinAddress = Hint < 0x80000000 ? 0 : Hint - 0x80000000;            //Use 0 if would underflow
    uint64_t MaxAddress = Hint > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                          std::numeric_limits<uint64_t>::max() : Hint + 0x80000000;

    DetourBuffer alloc_vec(LinuxAllocator(MinAddress, MaxAddress));
    return alloc_vec;
}

PLH::HookType PLH::x64DetourImp::GetType() const {
    return PLH::HookType::X64Detour;
}

PLH::Mode PLH::x64DetourImp::GetArchType() const {
    return PLH::Mode::x64;
}

uint8_t PLH::x64DetourImp::preferredPrologueLength() const {
    return 16;
}

uint8_t PLH::x64DetourImp::minimumPrologueLength() const {
    return 6;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::x64DetourImp::InstructionVector PLH::x64DetourImp::makeMinimumJump(const uint64_t address,
                                                                        const uint64_t destination,
                                                                        const uint64_t destHolder) const {
    PLH::Instruction::Displacement disp;
    disp.Relative = PLH::ADisassembler::CalculateRelativeDisplacement<int32_t>(address, destHolder, 5);

    std::vector<uint8_t> bytes(6);
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    memcpy(&bytes[2], &disp.Relative, 4);

    std::stringstream ss;
    ss << std::hex << "["<< destHolder << "]";

    memcpy((void*)&destHolder, &destination, 8);

    return {std::make_shared<PLH::Instruction>(address, disp, 2, true, bytes, "jmp", ss.str())};
}

PLH::x64DetourImp::InstructionVector PLH::x64DetourImp::makePreferredJump(const uint64_t address,
                                                                          const uint64_t destination) const {
    PLH::Instruction::Displacement zeroDisp = {0};
    uint64_t curInstAddress = address;

    std::vector<uint8_t> raxBytes = {0x50};
    auto pushRax = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false, raxBytes, "push", "rax");
    curInstAddress += pushRax->Size();

    std::stringstream ss;
    ss << std::hex << destination;

    std::vector<uint8_t> movRaxBytes(10);
    movRaxBytes[0] = 0x48;
    movRaxBytes[1] = 0xB8;
    memcpy(&movRaxBytes[2], &destination, 8);

    auto movRax = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false,
                                                     movRaxBytes, "mov", "rax, " + ss.str());
    curInstAddress += movRax->Size();

    std::vector<uint8_t> xchgBytes = { 0x48, 0x87, 0x04, 0x24 };
    auto xchgRspRax = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false,
                                                         xchgBytes, "xchg", "QWORD PTR [rsp],rax");
    curInstAddress += xchgRspRax->Size();

    std::vector<uint8_t> retBytes = {0xC3};
    auto ret = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false, retBytes, "ret", "");
    curInstAddress += ret->Size(); //shush, symmetry is sexy

    return {pushRax, movRax, xchgRspRax, ret};
}