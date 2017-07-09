//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64DetourImp.hpp"

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

uint8_t PLH::x64DetourImp::preferedPrologueLength() const {
    return 16;
}

uint8_t PLH::x64DetourImp::minimumPrologueLength() const {
    return 6;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destination should point to the memory location that *CONTAINS* the address to be jumped to.**/
std::shared_ptr<PLH::Instruction> PLH::x64DetourImp::makeMinimumSizeJump(const uint64_t address,
                                                                         const uint64_t destination) const {
    PLH::Instruction::Displacement disp;
    disp.Relative = PLH::ADisassembler::CalculateRelativeDisplacement<int32_t>(address, destination, 5);

    std::vector<uint8_t> bytes(6);
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    memcpy(&bytes[2], &disp.Relative, 4);

    std::stringstream ss;
    ss << std::hex << "["<< destination << "]";

    return std::make_shared<PLH::Instruction>(address, disp, 2, true, bytes, "jmp", ss.str());
}

std::shared_ptr<PLH::Instruction> PLH::x64DetourImp::makePreferedSizeJump(const uint64_t address,
                                                                          const uint64_t destination) const {
   //TODO: implement
}