//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x86DetourImp.hpp"
#include <cassert>

std::unique_ptr<PLH::x86DetourImp::DetourBuffer> PLH::x86DetourImp::makeMemoryBuffer(const uint64_t hint) {
    return std::make_unique<DetourBuffer>(); //any memory location will do for x86
}

PLH::HookType PLH::x86DetourImp::getType() const {
    return PLH::HookType::X86Detour;
}

PLH::Mode PLH::x86DetourImp::getArchType() const {
    return PLH::Mode::x86;
}

uint8_t PLH::x86DetourImp::preferredPrologueLength() const {
    return minimumPrologueLength();
}

uint8_t PLH::x86DetourImp::minimumPrologueLength() const {
    return 5;
}

PLH::JmpType PLH::x86DetourImp::minimumJumpType() const {
    return PLH::JmpType::Absolute;
}

PLH::JmpType PLH::x86DetourImp::preferredJumpType() const {
    return minimumJumpType();
}

void PLH::x86DetourImp::setIndirectHolder(const uint64_t holderAddress) {
    //no-op for x86 since all jumps are absolute
    assert(false); //infact you fucked up if it gets called
}

PLH::x86DetourImp::InstructionVector PLH::x86DetourImp::makeMinimumJump(const uint64_t address,
                                                                        const uint64_t destination) const {
    PLH::Instruction::Displacement disp;
    disp.Relative = PLH::ADisassembler::calculateRelativeDisplacement<int32_t>(address, destination, 5);

    std::vector<uint8_t> bytes(5);
    bytes[0] = 0xE9;
    memcpy(&bytes[1], &disp.Relative, 4);

    std::stringstream ss;
    ss << std::hex << destination;

    return {std::make_shared<PLH::Instruction>(address, disp, 1, true, bytes, "jmp", ss.str())};
}

PLH::x86DetourImp::InstructionVector PLH::x86DetourImp::makePreferredJump(const uint64_t address,
                                                                          const uint64_t destination) const {
    return makeMinimumJump(address, destination);
}
