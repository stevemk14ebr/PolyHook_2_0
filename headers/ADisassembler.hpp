//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include "headers/Instruction.hpp"
#include "headers/Enums.hpp"

#include <vector>

namespace PLH {
//Abstract Disassembler
class ADisassembler
{
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
    virtual std::vector<PLH::Instruction>
    disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) = 0;

    virtual void writeEncoding(const PLH::Instruction& instruction) const = 0;

    virtual bool isConditionalJump(const PLH::Instruction& inst) const = 0;

    template<typename T>
    static T calculateRelativeDisplacement(uint64_t from, uint64_t to, uint8_t insSize) {
        if (to < from)
            return 0 - (from - to) - insSize;
        return to - (from + insSize);
    }
protected:
    Mode          m_mode;
};
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
