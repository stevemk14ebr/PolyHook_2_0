//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Instruction.hpp"

uint8_t* PLH::x64DetourImp::makeMemoryBuffer(const uint64_t hint) {
    uint64_t MinAddress = hint < 0x80000000 ? 0 : hint - 0x80000000;            //Use 0 if would underflow
    uint64_t MaxAddress = hint > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                          std::numeric_limits<uint64_t>::max() : hint + 0x80000000;

	return 0; // TODO
}

PLH::Mode PLH::x64DetourImp::getArchType() const {
    return PLH::Mode::x64;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::insts_t PLH::x64DetourImp::makeMinimumJump(const uint64_t address, const uint64_t destination) const {
	return PLH::insts_t();
}

/**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
 * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
PLH::insts_t PLH::x64DetourImp::makePreferredJump(const uint64_t address, const uint64_t destination) const {
	return PLH::insts_t();
}