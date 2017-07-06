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
