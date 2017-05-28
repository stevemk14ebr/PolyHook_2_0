//
// Created by steve on 3/21/17.
//

#ifndef POLYHOOK_2_0_IDISASSEMBLER_HPP
#define POLYHOOK_2_0_IDISASSEMBLER_HPP

#include <vector>
#include "src/ErrorSystem.hpp"
#include "src/Instruction.hpp"
#include <memory>

namespace PLH {
    //Abstract Disassembler
    class ADisassembler {
    public:
        enum class Mode {
            x86,
            x64
        };

        ADisassembler(Mode mode)
        {
            m_Mode = mode;
        }

        virtual ~ADisassembler() = default;

        /**Disassemble a code buffer and return a vector holding the asm instructions info
         * @param FirstInstruction: The address of the first instruction
         * @param Start: The address of the code buffer
         * @param End: The address of the end of the code buffer
         * **/
        virtual std::vector<std::shared_ptr<PLH::Instruction>> Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) = 0;
        virtual void WriteEncoding(const PLH::Instruction& instruction) = 0;

        typedef PLH::EventDispatcher<void(const PLH::Message&)> tErrorHandler;
        virtual tErrorHandler& OnError()
        {
            return m_ErrorCallback;
        }
    protected:
        Mode m_Mode;
        tErrorHandler m_ErrorCallback;
    };
}
#endif //POLYHOOK_2_0_IDISASSEMBLER_HPP
