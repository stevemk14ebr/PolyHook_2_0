//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
#define POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP

#include <inttypes.h>
#include <string.h>
#include <memory>   //memset on linux
#include "src/ADisassembler.hpp"
#include "src/Maybe.hpp"
#include <capstone/include/capstone/capstone.h>

namespace PLH {
class CapstoneDisassembler : public ADisassembler
{
public:
    CapstoneDisassembler(ADisassembler::Mode mode) : ADisassembler(mode) {
        cs_mode capmode = (mode == ADisassembler::Mode::x64 ? CS_MODE_64 : CS_MODE_32);
        if (cs_open(CS_ARCH_X86, capmode, &m_CapHandle) != CS_ERR_OK)
            m_ErrorCallback.Invoke(PLH::Message("Capstone Init Failed"));

        cs_option(m_CapHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    virtual std::vector<std::shared_ptr<PLH::Instruction>>
    Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) override;

    virtual void WriteEncoding(const PLH::Instruction& instruction) override;

private:
    PLH::Maybe<int> GetParentIndex(const std::vector<std::shared_ptr<PLH::Instruction>>& Haystack, const uint64_t NeedleAddress) const {
        for (int i = 0; i < Haystack.size(); i++) {
            if (Haystack.at(i)->GetAddress() == NeedleAddress)
                return i;
        }
        function_fail("No parent found");
    }

    x86_reg GetIpReg() const {
        if (m_Mode == PLH::ADisassembler::Mode::x64)
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

    void CopyAndSExtendDisp(PLH::Instruction* Inst, const uint8_t Offset, const uint8_t Size, const bool ipRelative) const;

    csh m_CapHandle;
};
}

std::vector<std::shared_ptr<PLH::Instruction>>
PLH::CapstoneDisassembler::Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) {
    cs_insn* InsInfo = cs_malloc(m_CapHandle);
    std::vector<std::shared_ptr<PLH::Instruction>> InsVec;

    size_t Size = End - Start;
    while (cs_disasm_iter(m_CapHandle, (const uint8_t**)(&Start), &Size, &FirstInstruction, InsInfo)) {
//        printf("%" PRIx64 "[%d]: ", InsInfo->address, InsInfo->size);
//        for (uint_fast32_t j = 0; j < InsInfo->size; j++)
//            printf("%02X ", InsInfo->bytes[j]);
//        printf("%s %s\n", InsInfo->mnemonic, InsInfo->op_str);

        //Set later by 'SetDisplacementFields'
        PLH::Instruction::Displacement displacement;
        displacement.Absolute = 0;

        auto Inst = std::make_shared<PLH::Instruction>(InsInfo->address,
                                                       displacement,
                                                       0,
                                                       false,
                                                       InsInfo->bytes,
                                                       InsInfo->size,
                                                       InsInfo->mnemonic,
                                                       InsInfo->op_str);
        SetDisplacementFields(Inst.get(), InsInfo);

        auto ParentIndex = GetParentIndex(InsVec, Inst->GetDestination());
        if (ParentIndex.isOk())
            InsVec[ParentIndex.unwrap()]->AddChild(Inst);

        InsVec.push_back(std::move(Inst));
    }
    cs_free(InsInfo, 1);
    return InsVec;
}

void PLH::CapstoneDisassembler::WriteEncoding(const PLH::Instruction& instruction) {
    size_t                         DispSize   = instruction.Size() - instruction.GetDispOffset();
    PLH::Instruction::Displacement DispStruct = instruction.GetDisplacement();

    memcpy((void*)(instruction.GetAddress() + instruction.GetDispOffset()),
           instruction.IsDispRelative() ? (void*)&DispStruct.Relative : (void*)&DispStruct.Absolute,
           DispSize);
}

void PLH::CapstoneDisassembler::SetDisplacementFields(Instruction* Inst, const cs_insn* CapInst) const {
    cs_x86* x86 = &(CapInst->detail->x86);

    for (uint_fast32_t j = 0; j < x86->op_count; j++) {
        cs_x86_op* op = &(x86->operands[j]);
        if (op->type == X86_OP_MEM) {
            //Are we relative to instruction pointer?
            if (op->mem.base != GetIpReg())
                continue;

            const uint8_t Offset = x86->encoding.disp_offset;
            const uint8_t Size   = x86->encoding.disp_size;
            CopyAndSExtendDisp(Inst, Offset, Size, true);
        } else if (op->type == X86_OP_IMM) {
            //IMM types are like call 0xdeadbeef
            if (!HasGroup(CapInst, x86_insn_group::X86_GRP_JUMP) &&
                !HasGroup(CapInst, x86_insn_group::X86_GRP_CALL))
                continue;

            const uint8_t Offset = x86->encoding.imm_offset;
            const uint8_t Size   = x86->encoding.imm_size;

            //All x64 opcodes are RIP relative, otherwise in x86 IMM types are absolute
            bool ipRelative = false;
            #if __x86_64__ || __ppc64__
                ipRelative = true;
            #endif
            CopyAndSExtendDisp(Inst, Offset, Size, ipRelative);
        }
    }
}

void
PLH::CapstoneDisassembler::CopyAndSExtendDisp(PLH::Instruction* Inst, const uint8_t Offset, const uint8_t Size, const bool ipRelative) const {
    /* Sign extension necessary because we are storing numbers (possibly) smaller than uint64_t that may be negative.
     * 1 << (Size*8-1) dynamically calculates the position of the sign bit (furthest left) (our byte mask)
     * the Size*8 gives us the size in bits, i do -1 because zero based. Then left shift to set that bit to one.
     * Then & that with the value, the result will be positive if sign bit is set (negative displacement)
     * and 0 when sign bit not set (positive displacement)*/
    uint64_t displacement = 0;
    memcpy(&displacement, &Inst->GetBytes()[Offset], Size);

    uint64_t mask = (1U << (Size * 8 - 1));
    if (displacement & (1U << (Size * 8 - 1))) {
        /* sign extend if negative, requires that bits above Size*8 are zero,
         * if bits are not zero use x = x & ((1U << b) - 1) where x is a temp for displacement
         * and b is Size*8*/
        displacement = (displacement ^ mask) - mask;
    }
    //uint64_t Destination = Base + displacement  + Inst->Size();
    if(ipRelative)
        Inst->SetRelativeDisplacement(displacement);
    else
        Inst->SetAbsoluteDisplacement(displacement);
    Inst->SetDispOffset(Offset);
}

#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
