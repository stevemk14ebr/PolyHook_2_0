//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include "headers/Instruction.hpp"
#include "headers/Enums.hpp"

#include <vector>
#include <unordered_map>
#include <functional>

namespace PLH {
typedef std::unordered_map<uint64_t, insts_t> branch_map_t;

//Abstract Disassembler
class ADisassembler {
public:
	ADisassembler(PLH::Mode mode) {
		m_mode = mode;
	}

	virtual ~ADisassembler() = default;

	/**Disassemble a code buffer and return a vector holding the asm instructions info
	 * @param FirstInstruction: The address of the first instruction
	 * @param Start: The address of the code buffer
	 * @param End: The address of the end of the code buffer
	 * **/
	virtual insts_t disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) = 0;

	virtual void writeEncoding(const PLH::insts_t& instructions) const {
		for (const auto& inst : instructions)
			writeEncoding(inst);
	}

	virtual void writeEncoding(const Instruction& instruction) const = 0;

	virtual bool isConditionalJump(const Instruction& inst) const = 0;

	virtual bool isFuncEnd(const Instruction& inst) const = 0;

	branch_map_t getBranchMap() {
		return m_branchMap;
	}
protected:
	typename branch_map_t::mapped_type& updateBranchMap(uint64_t key, const Instruction& new_val) {
		branch_map_t::iterator it = m_branchMap.find(key);
		if (it != m_branchMap.end()) {
			it->second.push_back(new_val);
		} else {
			branch_map_t::mapped_type s;
			s.push_back(new_val);
			m_branchMap.emplace(key, s);
			return m_branchMap.at(key);
		}
		return it->second;
	}

	Mode          m_mode;

	/* key = address of instruction pointed at (dest of jump). Value = set of unique instruction branching to dest
	   Must only hold entries from the last segment disassembled. I.E clear every new call to disassemble
	*/
	branch_map_t m_branchMap;
};
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
