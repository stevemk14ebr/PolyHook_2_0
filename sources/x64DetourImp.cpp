//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Instruction.hpp"

PLH::Maybe<std::unique_ptr<PLH::x64DetourImp::DetourBuffer>> PLH::x64DetourImp::allocateMemory(const uint64_t hint) {
    uint64_t MinAddress = hint < 0x80000000 ? 0 : hint - 0x80000000;            //Use 0 if would underflow
    uint64_t MaxAddress = hint > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                          std::numeric_limits<uint64_t>::max() : hint + 0x80000000;

    return std::make_unique<DetourBuffer>(LinuxAllocator(MinAddress, MaxAddress));
}

PLH::HookType PLH::x64DetourImp::getType() const {
    return PLH::HookType::X64Detour;
}

PLH::Mode PLH::x64DetourImp::getArchType() const {
    return PLH::Mode::x64;
}

uint8_t PLH::x64DetourImp::preferredPrologueLength() const {
    return 16;
}

uint8_t PLH::x64DetourImp::minimumPrologueLength() const {
    return 6;
}

PLH::JmpType PLH::x64DetourImp::minimumJumpType() const {
    return PLH::JmpType::Indirect;
}

PLH::JmpType PLH::x64DetourImp::preferredJumpType() const {
    return PLH::JmpType::Absolute;
}

void PLH::x64DetourImp::setIndirectHolder(const uint64_t holderAddress) {
    m_indirectHolder = holderAddress;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::x64DetourImp::InstructionVector PLH::x64DetourImp::makeMinimumJump(const uint64_t address,
                                                                        const uint64_t destination) const {
    assert(m_indirectHolder);
    uint64_t destHolder = m_indirectHolder.unwrap();

    PLH::Instruction::Displacement disp = {0};
    disp.Relative = PLH::ADisassembler::calculateRelativeDisplacement<int32_t>(address, destHolder, 6);

    std::vector<uint8_t> bytes(6);
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    memcpy(&bytes[2], &disp.Relative, 4);

    std::stringstream ss;
    ss << std::hex << "[" << destHolder << "] ->" << destination;

    memcpy((void*)destHolder, &destination, 8);

    return {std::make_shared<PLH::Instruction>(address, disp, 2, true, bytes, "jmp", ss.str())};
}

PLH::x64DetourImp::InstructionVector PLH::x64DetourImp::makePreferredJump(const uint64_t address,
                                                                          const uint64_t destination) const {
    PLH::Instruction::Displacement zeroDisp       = {0};
    uint64_t                       curInstAddress = address;

    std::vector<uint8_t> raxBytes = {0x50};
    auto                 pushRax  = std::make_shared<PLH::Instruction>(curInstAddress,
                                                                       zeroDisp,
                                                                       0,
                                                                       false,
                                                                       raxBytes,
                                                                       "push",
                                                                       "rax");
    curInstAddress += pushRax->size();

    std::stringstream ss;
    ss << std::hex << destination;

    std::vector<uint8_t> movRaxBytes(10);
    movRaxBytes[0] = 0x48;
    movRaxBytes[1] = 0xB8;
    memcpy(&movRaxBytes[2], &destination, 8);

    auto movRax = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false,
                                                     movRaxBytes, "mov", "rax, " + ss.str());
    curInstAddress += movRax->size();

    std::vector<uint8_t> xchgBytes  = {0x48, 0x87, 0x04, 0x24};
    auto                 xchgRspRax = std::make_shared<PLH::Instruction>(curInstAddress, zeroDisp, 0, false,
                                                                         xchgBytes, "xchg", "QWORD PTR [rsp],rax");
    curInstAddress += xchgRspRax->size();

    std::vector<uint8_t> retBytes = {0xC3};
    auto                 ret      = std::make_shared<PLH::Instruction>(curInstAddress,
                                                                       zeroDisp,
                                                                       0,
                                                                       false,
                                                                       retBytes,
                                                                       "ret",
                                                                       "");
    curInstAddress += ret->size(); //shush, symmetry is sexy

    // #self_documenting_code #it_exists
    return {pushRax, movRax, xchgRspRax, ret};
}