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