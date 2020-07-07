//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
#define POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP

#include "polyhook2/ADisassembler.hpp"

#include <capstone/capstone.h>

#include <string.h>
#include <iostream> //for debug printing
#include <limits>
#include <cassert>

namespace PLH {

class CapstoneDisassembler : public ADisassembler {
public:
	CapstoneDisassembler(const PLH::Mode mode);

	virtual ~CapstoneDisassembler();

	virtual std::vector<PLH::Instruction>
		disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end, const MemAccessor& accessor) override;
private:
	x86_reg getIpReg() const {
		if (m_mode == PLH::Mode::x64)
			return X86_REG_RIP;
		else //if(m_Mode == PLH::ADisassembler::Mode::x86)
			return X86_REG_EIP;
	}

	bool hasGroup(const cs_insn* inst, const x86_insn_group grp) const {
		const uint8_t grpSize = inst->detail->groups_count;

		for (int i = 0; i < grpSize; i++) {
			if (inst->detail->groups[i] == grp)
				return true;
		}
		return false;
	}

	void setDisplacementFields(Instruction& inst, const cs_insn* capInst) const;

	/* For immediate types capstone gives us only the final destination, but *we* care about the base + displacement values.
	 * Immediates can be encoded either as some value relative to a register, or a straight up hardcoded address, we need
	 * to figure out which so that we can do code relocation later. To deconstruct the info we need first we read the imm value byte
	 * by byte out of the instruction, if that value is less than what capstone told us is the destination then we know that it is relative and we have to add the base.
	 * Otherwise if our retreived displacement is equal to the given destination then it is a true absolute jmp/call (only possible in x64),
	 * if it's greater then something broke.*/
	void copyDispSx(PLH::Instruction& inst,
					const uint8_t offset,
					const uint8_t size,
					const int64_t immDestination) const;

	csh m_capHandle;
};
}
#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
