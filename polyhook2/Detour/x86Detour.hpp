//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include <sstream>
#include <algorithm>
#include <functional>
using namespace std::placeholders;

#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Instruction.hpp"
#include "polyhook2/ADisassembler.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/MemProtector.hpp"

namespace PLH {

class x86Detour : public Detour {
public:
	x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	x86Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);
	virtual ~x86Detour() = default;
	virtual bool hook() override;

	Mode getArchType() const override;

	uint8_t getJmpSize() const;
private:
	bool makeTrampoline(insts_t& prologue, insts_t& trampolineOut);
};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
