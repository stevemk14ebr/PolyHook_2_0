//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include "headers/ErrorSystem.hpp"
#include "headers/Instruction.hpp"
#include "headers/Enums.hpp"

#include <vector>
#include <memory>

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
    virtual std::vector<std::shared_ptr<PLH::Instruction>>
    disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) = 0;

    virtual void writeEncoding(const PLH::Instruction& instruction) = 0;

    virtual bool isConditionalJump(const PLH::Instruction& inst) const = 0;

    template<typename T>
    static T calculateRelativeDisplacement(uint64_t from, uint64_t to, uint8_t insSize) {
        if (to < from)
            return 0 - (from - to) - insSize;
        return to - (from + insSize);
    }

    typedef PLH::EventDispatcher<void(const PLH::Message&)> tErrorHandler;

    virtual tErrorHandler& OnError() {
        return m_errorCallback;
    }

protected:
    Mode          m_mode;
    tErrorHandler m_errorCallback;
};
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
