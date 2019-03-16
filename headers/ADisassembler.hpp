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
	virtual ~ADisassembler() = default;

	/**Disassemble a code buffer and return a vector holding the asm instructions info
	 * @param FirstInstruction: The address of the first instruction
	 * @param Start: The address of the code buffer
	 * @param End: The address of the end of the code buffer
	 * **/
	virtual insts_t disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) = 0;

	virtual void writeEncoding(const PLH::insts_t& instructions) const = 0;
	
	virtual void writeEncoding(const Instruction& instruction) const = 0;

	virtual bool isConditionalJump(const Instruction& inst) const = 0;

	virtual bool isFuncEnd(const Instruction& inst) const = 0;

	virtual branch_map_t getBranchMap() const = 0; 
};
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
