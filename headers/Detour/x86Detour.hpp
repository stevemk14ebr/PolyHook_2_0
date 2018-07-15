//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

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

class x86Detour : public Detour {
public:
	x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	x86Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	virtual bool hook() override;

	Mode getArchType() const;

	insts_t makeJmp(const uint64_t address, const uint64_t destination) const;

	uint8_t getJmpSize() const;
private:
	std::optional<insts_t> makeTrampoline(insts_t& prologue);
};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
