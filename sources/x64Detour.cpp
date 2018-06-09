//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64Detour.hpp"

PLH::x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

PLH::x64Detour::x64Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

uint8_t* PLH::x64Detour::makeTrampolineNear(const uint64_t hint, const uint64_t size) const {
    uint64_t MinAddress = hint < 0x80000000 ? 0 : hint - 0x80000000;            //Use 0 if would underflow
    uint64_t MaxAddress = hint > std::numeric_limits<uint64_t>::max() - 0x80000000 ? 
                          std::numeric_limits<uint64_t>::max() : hint + 0x80000000; //use max if would overflow

	return 0; // TODO
}

PLH::Mode PLH::x64Detour::getArchType() const {
    return PLH::Mode::x64;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::insts_t PLH::x64Detour::makeMinimumJump(const uint64_t address, const uint64_t destination) const {
	return PLH::insts_t();
}

/**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
 * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
PLH::insts_t PLH::x64Detour::makePreferredJump(const uint64_t address, const uint64_t destination) const {
	return PLH::insts_t();
}

bool PLH::x64Detour::hook() {
	return true;
}

bool PLH::x64Detour::unHook() {
	return true;
}