//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X64DETOUR_HPP
#define POLYHOOK_2_X64DETOUR_HPP

#include <sstream>
#include <algorithm>
#include <functional>
using namespace std::placeholders;

#include "headers/Detour/ADetour.hpp"
#include "headers/Enums.hpp"
#include "headers/Instruction.hpp"
#include "headers/ADisassembler.hpp"
#include "headers/ErrorLog.hpp"
#include "headers/MemProtector.hpp"

namespace PLH {

class x64Detour : public Detour {
public:
	x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	virtual bool hook() override;

	Mode getArchType() const;

	insts_t makeMinimumJump(const uint64_t address, const uint64_t destination, const uint64_t destHolder) const;

	insts_t makePreferredJump(const uint64_t address, const uint64_t destination) const;

	uint8_t getMinJmpSize() const;

	uint8_t getPrefJmpSize() const;
private:
	std::optional<insts_t> makeTrampoline(insts_t& prologue);
};
}
#endif //POLYHOOK_2_X64DETOUR_HPP
