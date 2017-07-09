//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x86DetourImp.hpp"

PLH::Maybe<PLH::x86DetourImp::DetourBuffer> PLH::x86DetourImp::AllocateMemory(const uint64_t Hint) {
    return DetourBuffer(); //any memory location will do for x86
}

PLH::HookType PLH::x86DetourImp::GetType() const {
    return PLH::HookType::X86Detour;
}

PLH::Mode PLH::x86DetourImp::GetArchType() const {
    return PLH::Mode::x86;
}

uint8_t PLH::x86DetourImp::preferedPrologueLength() const {
    return minimumPrologueLength();
}

uint8_t PLH::x86DetourImp::minimumPrologueLength() const {
    return 5;
}

std::shared_ptr<PLH::Instruction> PLH::x86DetourImp::makeMinimumSizeJump(const uint64_t address,
                                                                         const uint64_t destination) const {
    PLH::Instruction::Displacement disp;
    disp.Relative = PLH::ADisassembler::CalculateRelativeDisplacement<int32_t>(address, destination, 5);

    std::vector<uint8_t> bytes(5);
    bytes[0] = 0xE9;
    memcpy(&bytes[1], &disp.Relative, 4);

    std::stringstream ss;
    ss << std::hex << destination;

    return std::make_shared<PLH::Instruction>(address, disp, 1, true, bytes, "jmp", ss.str());
}

std::shared_ptr<PLH::Instruction> PLH::x86DetourImp::makePreferedSizeJump(const uint64_t address,
                                                                          const uint64_t destination) const {
    return makeMinimumSizeJump(address, destination);
}
