//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
#define POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP

#include "headers/ADisassembler.hpp"
#include "headers/Maybe.hpp"

#include <capstone/include/capstone/capstone.h>

#include <inttypes.h>
#include <string.h>
#include <memory>   //memset on linux
#include <iostream> //for debug printing

namespace PLH {
class CapstoneDisassembler : public ADisassembler
{
public:
    CapstoneDisassembler(PLH::Mode mode) : ADisassembler(mode) {
        cs_mode capmode = (mode == PLH::Mode::x64 ? CS_MODE_64 : CS_MODE_32);
        if (cs_open(CS_ARCH_X86, capmode, &m_CapHandle) != CS_ERR_OK)
            m_ErrorCallback.Invoke(PLH::Message("Capstone Init Failed"));

        cs_option(m_CapHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    virtual std::vector<std::shared_ptr<PLH::Instruction>>
    Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) override;

    virtual void WriteEncoding(const PLH::Instruction& instruction) override;

private:
    /**When new instructions are inserted we have to re-itterate the list and add
     * a child to an instruction if the new instruction points to it**/
    void ModifyParentIndices(std::vector<std::shared_ptr<PLH::Instruction>>& Haystack,
                                        std::shared_ptr<PLH::Instruction>& NewInstruction) const {
        for (int i = 0; i < Haystack.size(); i++) {
            //Check for things that the new instruction may point too
            if (Haystack.at(i)->GetAddress() == NewInstruction->GetDestination())
                Haystack.at(i)->AddChild(NewInstruction);

            //Check for things that may point to the new instruction
            if(Haystack.at(i)->GetDestination() == NewInstruction->GetAddress())
                NewInstruction->AddChild(Haystack.at(i));
        }
    }

    x86_reg GetIpReg() const {
        if (m_Mode == PLH::Mode::x64)
            return X86_REG_RIP;
        else //if(m_Mode == PLH::ADisassembler::Mode::x86)
            return X86_REG_EIP;
    }

    bool HasGroup(const cs_insn* Inst, const x86_insn_group grp) const {
        uint8_t  GrpSize = Inst->detail->groups_count;
        for (int i       = 0; i < GrpSize; i++) {
            if (Inst->detail->groups[i] == grp)
                return true;
        }
        return false;
    }

    void SetDisplacementFields(Instruction* Inst, const cs_insn* CapInst) const;

    /* For immediate types capstone gives us only the final destination, but *we* care about the base + displacement values.
     * Immediates can be encoded either as some value relative to a register, or a straight up hardcoded address, we need
     * to figure out which so that we can do code relocation later. To deconstruct the info we need first we read the imm value byte
     * by byte out of the instruction, if that value is less than what capstone told us is the destination then we know that it is relative and we have to add the base.
     * Otherwise if our retreived displacement is equal to the given destination then it is a true absolute jmp/call (only possible in x64),
     * if it's greater then something broke.*/
    void CopyAndSExtendDisp(PLH::Instruction* Inst, const uint8_t Offset, const uint8_t Size, const int64_t immDestination) const;

    csh m_CapHandle;
};
}
#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
