//
// Created by steve on 7/5/17.
//
#include "headers/CapstoneDisassembler.hpp"

std::vector<std::shared_ptr<PLH::Instruction>>
PLH::CapstoneDisassembler::Disassemble(uint64_t FirstInstruction, uint64_t Start, uint64_t End) {
    cs_insn* InsInfo = cs_malloc(m_CapHandle);
    std::vector<std::shared_ptr<PLH::Instruction>> InsVec;

    uint64_t Size = End - Start;
    while (cs_disasm_iter(m_CapHandle, (const uint8_t**)(&Start), &Size, &FirstInstruction, InsInfo)) {
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

    /* When the retrieved displacement is < immDestination we know that the base address is included
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

bool PLH::CapstoneDisassembler::isConditionalJump(const PLH::Instruction& instruction) const {
    //http://unixwiz.net/techtips/x86-jumps.html
    if (instruction.Size() < 1)
        return false;

    std::vector<uint8_t> bytes = instruction.GetBytes();
    if (bytes[0] == 0x0F && instruction.Size() > 1)
    {
        if (bytes[1] >= 0x80 && bytes[1] <= 0x8F)
            return true;
    }

    if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
        return true;

    if (bytes[0] == 0xE3)
        return true;

    return false;
}