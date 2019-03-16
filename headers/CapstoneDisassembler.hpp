//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
#define POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP

#include "headers/ADisassembler.hpp"

#include <capstone/include/capstone/capstone.h>

#include <string.h>
#include <iostream> //for debug printing
#include <limits>
#include <cassert>
#include <algorithm>

namespace PLH {

class CapstoneDisassembler : public ADisassembler {
public:
	CapstoneDisassembler(PLH::Mode mode)
	: m_mode(mode) {
		cs_mode capmode = (mode == PLH::Mode::x64 ? CS_MODE_64 : CS_MODE_32);
		if (cs_open(CS_ARCH_X86, capmode, &m_capHandle) != CS_ERR_OK)
			printf("error opening cap\n");

		cs_option(m_capHandle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	~CapstoneDisassembler() override;

	virtual std::vector<PLH::Instruction>
		disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) override;

	void writeEncoding(const PLH::Instruction& instruction) const override;
	
	void writeEncoding(const PLH::insts_t& instructions) const override;

	bool isConditionalJump(const PLH::Instruction& instruction) const override;

	bool isFuncEnd(const PLH::Instruction& instructioni) const override;
	
	branch_map_t getBranchMap() const override;
	
private:
	x86_reg getIpReg() const;

	bool hasGroup(const std::shared_ptr<cs_insn>& inst, const x86_insn_group grp) const;

	void setDisplacementFields(Instruction& inst, const std::shared_ptr<cs_insn>& capInst) const;

	/* For immediate types capstone gives us only the final destination, but *we* care about the base + displacement values.
	 * Immediates can be encoded either as some value relative to a register, or a straight up hardcoded address, we need
	 * to figure out which so that we can do code relocation later. To deconstruct the info we need first we read the imm value byte
	 * by byte out of the instruction, if that value is less than what capstone told us is the destination then we know that it is relative and we have to add the base.
	 * Otherwise if our retreived displacement is equal to the given destination then it is a true absolute jmp/call (only possible in x64),
	 * if it's greater then something broke.*/
	void copyDispSX(PLH::Instruction& inst,
					const uint8_t offset,
					const uint8_t size,
					const int64_t immDestination) const;
	
	typename branch_map_t::mapped_type& updateBranchMap(uint64_t key, const Instruction& new_val);
	
	/* key = address of instruction pointed at (dest of jump). Value = set of unique instruction branching to dest
	 Must only hold entries from the last segment disassembled. I.E clear every new call to disassemble
	 */
	branch_map_t m_branchMap;
	csh m_capHandle;
	Mode          m_mode;
};
}
#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
