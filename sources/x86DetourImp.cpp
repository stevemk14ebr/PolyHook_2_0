//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x86DetourImp.hpp"
#include <cassert>

PLH::Mode PLH::x86DetourImp::getArchType() const {
    return PLH::Mode::x86;
}

PLH::insts_t PLH::x86DetourImp::makeMinimumJump(const uint64_t address, const uint64_t destination) const {
	return PLH::insts_t();
}

PLH::insts_t PLH::x86DetourImp::makePreferredJump(const uint64_t address, const uint64_t destination) const {
    return makeMinimumJump(address, destination);
}
