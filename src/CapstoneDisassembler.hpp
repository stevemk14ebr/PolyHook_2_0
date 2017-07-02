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

//debug
#include <iostream>

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

std::vector<std::shared_ptr<PLH::Instruction>>
PLH::CapstoneDisassembler::Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) {
    cs_insn* InsInfo = cs_malloc(m_CapHandle);
    std::vector<std::shared_ptr<PLH::Instruction>> InsVec;

    size_t Size = End - Start;
    while (cs_disasm_iter(m_CapHandle, (const uint8_t**)(&Start), &Size, &FirstInstruction, InsInfo)) {
        printf("%" PRIx64 "[%d]: ", InsInfo->address, InsInfo->size);
        for (uint_fast32_t j = 0; j < InsInfo->size; j++)
            printf("%02X ", InsInfo->bytes[j]);
        printf("%s %s\n", InsInfo->mnemonic, InsInfo->op_str);

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
        ModifyParentIndices(InsVec, Inst);

        InsVec.push_back(std::move(Inst));
    }
    printf("\n\n");
    cs_free(InsInfo, 1);
    return InsVec;
}

/**Write the raw bytes of the given instruction into the memory specified by the
 * instruction's address. If the address value of the instruction has been changed
 * since the time it was decoded this will copy the instruction to a new memory address.
 * This will not automatically do any code relocation, all relocation logic should
 * first modify the byte array, and then call write encoding, proper order to relocate
 * an instruction should be disasm instructions -> set relative/abolsute displacement() ->
 * writeEncoding(). It is done this way so that these operations can be made transactional**/
void PLH::CapstoneDisassembler::WriteEncoding(const PLH::Instruction& instruction) {
    memcpy((void*)instruction.GetAddress(), &instruction.GetBytes()[0], instruction.Size());
}

/**If an instruction is a jmp/call variant type this will set it's displacement fields to the
 * appropriate values. All other types of instructions are ignored and is no-op. More specifically
 * this determines if an instruction is a jmp/call variant, and then further if it is is jumping via
 * memory or immediate, and then finally if that mem/imm is encoded via a displacement relative to
 * the instruction pointer, or directly to an absolute address**/
void PLH::CapstoneDisassembler::SetDisplacementFields(PLH::Instruction* Inst, const cs_insn* CapInst) const {
    cs_x86* x86 = &(CapInst->detail->x86);

    for (uint_fast32_t j = 0; j < x86->op_count; j++) {
        cs_x86_op* op = &(x86->operands[j]);
        if (op->type == X86_OP_MEM) {
            //Are we relative to instruction pointer?
            //mem are types like jmp [rip + 0x4] where location is dereference-d
            if (op->mem.base != GetIpReg())
                continue;

            const uint8_t Offset = x86->encoding.disp_offset;
            const uint8_t Size   = x86->encoding.disp_size;
            CopyAndSExtendDisp(Inst, Offset, Size, std::numeric_limits<int64_t>::max());
        } else if (op->type == X86_OP_IMM) {
            //IMM types are like call 0xdeadbeef where they jmp straight to some location
            if (!HasGroup(CapInst, x86_insn_group::X86_GRP_JUMP) &&
                !HasGroup(CapInst, x86_insn_group::X86_GRP_CALL))
                continue;

            const uint8_t Offset = x86->encoding.imm_offset;
            const uint8_t Size   = x86->encoding.imm_size;
            CopyAndSExtendDisp(Inst, Offset, Size, op->imm);
        }
    }
}

/**Copies the displacement bytes from memory, and sign extends these values if necessary**/
void PLH::CapstoneDisassembler::CopyAndSExtendDisp(PLH::Instruction* Inst, const uint8_t Offset, const uint8_t Size, const int64_t immDestination) const {
    /* Sign extension necessary because we are storing numbers (possibly) smaller than int64_t that may be negative.
     * If we did not do this, then the sign bit would be in the incorrect place for an int64_t.
     * 1 << (Size*8-1) dynamically calculates the position of the sign bit (furthest left) (our byte mask)
     * the Size*8 gives us the size in bits, i do -1 because zero based. Then left shift to set that bit to one.
     * Then & that with the calculated mask to check if the sign bit is set in the retrieved displacement,
     * the result will be positive if sign bit is set (negative displacement)
     * and 0 when sign bit not set (positive displacement)*/
    int64_t displacement = 0;
    memcpy(&displacement, &Inst->GetBytes()[Offset], Size);

    uint64_t mask = (1U << (Size * 8 - 1));
    if (displacement & (1U << (Size * 8 - 1))) {
        /* sign extend if negative, requires that bits above Size*8 are zero,
         * if bits are not zero use x = x & ((1U << b) - 1) where x is a temp for displacement
         * and b is Size*8*/
        displacement = (displacement ^ mask) - mask; //xor clears sign bit, subtraction makes number negative again but in the int64 range
    }

    Inst->SetDisplacementOffset(Offset);

    /*When the retrieved displacement is < immDestination we know that the base address is included
     * in the destinations calculation. By definition this means it is relative. Otherwise it is absolute*/
    if(displacement < immDestination) {
        if(immDestination != std::numeric_limits<int64_t>::max())
            assert(displacement + Inst->GetAddress() + Inst->Size() == immDestination);
        Inst->SetRelativeDisplacement(displacement);
    }else {
        assert(((uint64_t)displacement) == ((uint64_t)immDestination));
        Inst->SetAbsoluteDisplacement((uint64_t)displacement);
    }
}

#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
