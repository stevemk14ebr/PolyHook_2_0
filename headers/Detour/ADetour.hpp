//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include "headers/CapstoneDisassembler.hpp"
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Detour/x86DetourImp.hpp"
#include "headers/MemoryAllocation/MemoryProtector.hpp"
#include "headers/Finally.hpp"
#include "headers/Maybe.hpp"

#include <map>

/**
 * All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/

namespace PLH {

/**
 *  It is required that the Architectural implementation's preferredJump type be an absolute
 *  jump, in order to simplify logic. The minimum jump type may be indirect
 * **/
typedef std::vector<std::shared_ptr<PLH::Instruction>> InstructionVector;

template<typename Architecture, typename Disassembler = PLH::CapstoneDisassembler>
class Detour : public PLH::IHook
{
public:
    typedef typename Architecture::DetourBuffer ArchBuffer;

    Detour(const uint64_t fnAddress, const uint64_t fnCallback);

    Detour(const char* fnAddress, const char* fnCallback);

    virtual bool hook() override;

    virtual bool unHook() override;

    virtual PLH::HookType getType() override;

    template<typename T>
    T getOriginal() {
        assert(m_trampoline.isOk());
        return (T)m_trampoline.unwrap().data();
    }

private:
    /*  These are shared_ptrs because the can point to each other. Internally PLH::Instruction's
        store non-owning "child" pointers. If they lived on the stack the logic to do that would be
        much more complicated.*/

    /**Walks the given vector of instructions and rounds up to the smallest byte count that won't split
     * any instructions. If the given instruction vector rounded up is >= lengthWanted then the lengthWanted
     * parameter is set to the rounded up length in bytes. If the roundedUp length is smaller than lengthWanted
     * then lengthWanted is untouched and the functions returns a failed Maybe. Prologue walking will stop
     * if function end is detected (currently searches for ret).**/
    PLH::Maybe<InstructionVector> calcPrologueMinLength(const InstructionVector& functionInsts, size_t& lengthWanted);

    /**Walks the prologue for instructions in the functions body that jump back into the prologue section that will
     * be overwritten by the jump to the callback. This overwritten section is calculated to be the address of the first
     * instruction given in the instruction vector to that address + an offset. I.E. [firstAddr, firstAddr + firstUnusedInst).
     * If it is detected that any instructions jump back into the prologue the a jump table is built and those instructions
     * pointed to an entry in the jump tables. Room for this jump table is made by expanding the prologue area copied
     * over to the callback. The return value is a vector of instructions that should overwrite the originally prologue**/
    PLH::Maybe<InstructionVector>
    insertPrologueJumpTable(const InstructionVector& functionInsts, size_t& overWrittenBytes);

    bool shouldMakePrologueJmpTable(const InstructionVector& functionInsts, size_t& overWrittenBytes);

    void dbgPrintInstructionVec(const std::string& name, const InstructionVector& instructionVector);

    uint64_t               m_fnAddress;
    uint64_t               m_fnCallback;
    bool                   m_hooked;
    PLH::Maybe<ArchBuffer> m_trampoline;
    PLH::Maybe<ArchBuffer> m_prologueJumpTable;
    /* Will only have prologueJumpTable if we have cyclic prologue jumps
     * and if the architecures minimum jump is indirect.*/

    Architecture m_archImpl;
    Disassembler m_disassembler;

    void insertTrampolineJumpTable(const InstructionVector& conditionalJumpsToFix, const int64_t trampolineDelta);

    int64_t insertTrampolinePrologue(const InstructionVector& prologueInstructions);
};


template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) :
        m_archImpl(), m_disassembler(m_archImpl.GetArchType()) {
    assert(hookAddress != NULL && callbackAddress != NULL);
    m_fnAddress  = hookAddress;
    m_fnCallback = callbackAddress;
    m_hooked     = false;
}

template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const char* hookAddress, const char* callbackAddress) :
        m_archImpl(), m_disassembler(m_archImpl.getArchType()) {
    assert(hookAddress != nullptr && callbackAddress != nullptr);
    m_fnAddress  = (uint64_t)hookAddress;
    m_fnCallback = (uint64_t)callbackAddress;
    m_hooked     = false;
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::hook() {

    // Allocate some memory near the callback for the trampoline
    m_trampoline = m_archImpl.makeMemoryBuffer(m_fnCallback);
    assert(m_trampoline.isOk());

    // disassemble the function to hook
    InstructionVector instructions = m_disassembler.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100);
    if (instructions.size() <= 0) {
        sendError("Disassembler unable to decode any valid instructions for given fnAddress");
        return false;
    }

    dbgPrintInstructionVec("Original function: ", instructions);

    // Always do the smallest jump to avoid extra complexities
    bool    jumpAbsolute   = m_archImpl.minimumJumpType() == PLH::JmpType::Absolute;
    uint8_t jumpLength     = m_archImpl.minimumPrologueLength();
    size_t  prologueLength = jumpLength;

    auto maybePrologueInstructions = calcPrologueMinLength(instructions, prologueLength);
    if (!maybePrologueInstructions) {
        sendError(maybePrologueInstructions.unwrapError());
        return false;
    }
    assert(prologueLength >= jumpLength);

    InstructionVector prologueInstructions = std::move(maybePrologueInstructions).unwrap();
    dbgPrintInstructionVec("Prologue: ", prologueInstructions);

    if (shouldMakePrologueJmpTable(instructions, prologueLength)) {
        insertPrologueJumpTable(instructions, prologueLength);
        return false;
    }

    // Count # of entries that will be in the jump table
    InstructionVector conditionalJumpsToFix;
    for (const auto& inst : prologueInstructions) {
        if (m_disassembler.isConditionalJump(*inst))
            conditionalJumpsToFix.push_back(inst);
    }

    /* reserve space for relocated prologue + jmp to fnAddress.Body + N jump table entries
     * + optional indirect location if our jump type is an indirect style (!Absolute).
     * DO NOT remove this reservation, without it the underlying vector could relocate the
     * trampoline without letting us know on a push_back or insert, and all our precious
     * fixups are out the window.*/
    size_t reserveSize = prologueLength +
                         m_archImpl.preferredPrologueLength() +
                         (conditionalJumpsToFix.size() * m_archImpl.preferredPrologueLength())
                         + (jumpAbsolute ? 0 : 8);
    try {
        m_trampoline.unwrap().reserve(reserveSize);
    }catch (const PLH::AllocationFailure& ex) {
        sendError("Failed to allocate trampoline buffer");
        return false;
    }
    int64_t trampolineDelta = insertTrampolinePrologue(prologueInstructions);

    // Insert the jmp to fnAddress.Body from the trampoline
    InstructionVector bodyJump = m_archImpl.makePreferredJump((uint64_t)m_trampoline.unwrap().data() +
                                                              m_trampoline.unwrap().size(),
                                                              m_fnAddress + jumpLength);

    for (const auto& inst : bodyJump)
        m_trampoline.unwrap().insert(m_trampoline.unwrap().end(), inst->getBytes().begin(), inst->getBytes().end());

    insertTrampolineJumpTable(conditionalJumpsToFix, trampolineDelta);

    // Make the fnAddress's memory page writeable
    uint64_t fnAddressPage = (uint64_t)PLH::AlignDownwards((char*)m_fnAddress, getpagesize());

    PLH::MemoryProtector<PLH::UnixMemProtImp> memoryProtectorFn(fnAddressPage,
                                                                getpagesize(),
                                                                PLH::ProtFlag::R | PLH::ProtFlag::W | PLH::ProtFlag::X);
    if (!memoryProtectorFn.originalProt()) {
        sendError("Failed to make fnAddress' memory page writable");
        return false;
    }

    /* Overwrite the prologue with the jmp to the callback. Always
     * use the smallest jump type we can, otherwise we can get into
     * complex cases where condition branches point back to parts of
     * our prologue that were overwritten. This simplifiest it if
     * the jump is always small*/
    InstructionVector detourJump;

    if (jumpAbsolute) {
        detourJump = m_archImpl.makeMinimumJump(m_fnAddress, m_fnCallback);
    } else {
        m_archImpl.setIndirectHolder((uint64_t)m_trampoline.unwrap().data() + m_trampoline.unwrap().size());
        detourJump = m_archImpl.makeMinimumJump(m_fnAddress, m_fnCallback);
    }

    for (const auto& inst : detourJump)
        m_disassembler.writeEncoding(*inst);

    // Nop the space between jmp and end of prologue
    std::memset((char*)(m_fnAddress + jumpLength), 0x90, prologueLength - jumpLength);

    if (m_debugSet) {
        std::cout << "fnAddress: " << std::hex << m_fnAddress << " fnCallback: " << m_fnCallback <<
                  " trampoline: " << (uint64_t)m_trampoline.unwrap().data() << " delta: "
                  << trampolineDelta << std::dec << std::endl;

        InstructionVector trampolineInst = m_disassembler.disassemble((uint64_t)m_trampoline.unwrap().data(),
                                                                      (uint64_t)m_trampoline.unwrap().data(),
                                                                      (uint64_t)m_trampoline.unwrap().data() +
                                                                      m_trampoline.unwrap().size());
        dbgPrintInstructionVec("Trampoline: ", trampolineInst);

        // Go a little past prologue to see if we corrupted anything
        InstructionVector newPrologueInst = m_disassembler.disassemble(m_fnAddress,
                                                                       m_fnAddress,
                                                                       m_fnAddress + prologueLength + 10);
        dbgPrintInstructionVec("New Prologue: ", newPrologueInst);

        InstructionVector callbackInst = m_disassembler.disassemble(m_fnCallback,
                                                                    m_fnCallback,
                                                                    m_fnCallback + 100);
        dbgPrintInstructionVec("Callback: ", callbackInst);
    }

    /* If this happened the vector was somehow resized.
     * This would be very bad for us, since we manually
     * mutate instruction displacements. Therefore
     * moving the trampoline makes our fixups invalid.
     * Figure out why this happened or stuff blows up*/
    if (m_trampoline.unwrap().capacity() != reserveSize) {
        assert(false);
        sendError("Internal Error: Trampoline vector unexpectedly relocated");
        return false;
    }

    return true;

    /** Before Hook:                                                After hook:
     *
     * --------fnAddress--------                                    --------fnAddress--------
     * |    prologue           |                                   |    jmp fnCallback      | <- this may be an indirect jmp
     * |    ...body...         |      ----> Converted into ---->   |    ...jump table...    | if it is, it reads the final
     * |                       |                                   |    ...body...          |  dest from end of trampoline (optional indirect loc)
     * |    ret                |                                   |    ret                 |
     * -------------------------                                   --------------------------
     *                                                                           ^ jump table may not exist.
     *                                                                           If it does, and it uses indirect style
     *                                                                           jumps then prologueJumpTable exists.
     *                                                                           prologueJumpTable holds pointers
     *                                                                           to where the indirect jump actually
     *                                                                           lands.
     *
     *                               Created during hooking:
     *                              --------Trampoline--------
     *                              |     prologue            | Executes fnAddress's prologue (we overwrote it with jmp)
     *                              |     jmp fnAddress.body  | Jmp back to first address after the overwritten prologue
     *                              |  ...jump table...       | Long jmp table that short jmps in prologue point to
     *                              |  optional indirect loc  | may or may not exist depending on jmp type we used
     *                              --------------------------
     *
     *                              Conditionally exists:
     *                              ----prologueJumpTable-----
     *                              |    jump_holder1       | -> points into Trampolinee.prologue
     *                              |    jump_holder2       | -> points into Trampoline.prologue
     *                              |       ...             |
     *                              ------------------------
     *
     *
     *                      Example jmp table (with an example prologue, this prologue lives in trampoline):
     *
     *        Prologue before fix:          Prologue after fix:
     *        ------prologue-----           ------prologue----          ----jmp table----
     *        push ebp                      push ebp                    jump_table.Entry1: long jmp original je address + 0x20
     *        mov ebp, esp                  mov ebp, esp
     *        cmp eax, 1                    cmp eax, 1
     *        je 0x20                       je jump_table.Entry1
     *
     *        This jump table is needed because the original je instruction's displacement has a max vale of 0x80. It's
     *        extremely likely that our Trampoline was not placed +-0x80 bytes away from fnAddress. Therefore we have
     *        to add an intermediate long jmp so that the moved je will still jump to where it originally pointed. To
     *        do this we insert a jump table at the end of the trampoline, there's N entrys where conditional jmp N points
     *        to jump_table.EntryN.
     *
     *
     *                          User Implements callback as C++ code
     *                              --------fnCallback--------
     *                              | ...user defined code... |
     *                              |   return Trampoline     |
     *                              |                         |
     *                              --------------------------
     * **/
}

/* Copy instructions from the fnAddress' prologue to the trampoline, original prologue is left untouched.
 * Relocation of RIP/EIP relative instructions in the trampoline's copy is performed, excluding conditional jumps.
 * Conditional jumps are fixed later via the jump table. This returns how far away the first instruction in
 * the trampolines prologue is from the first instruction of fnAddress' prologue - in bytes.*/
template<typename Architecture, typename Disassembler>
int64_t Detour<Architecture, Disassembler>::insertTrampolinePrologue(const InstructionVector& prologueInstructions) {
    assert(m_trampoline.isOk());

    int64_t trampolineDelta = 0;
    for (auto& inst : prologueInstructions) {
        // Copy instruction into the trampoline (they will be malformed)
        m_trampoline.unwrap().insert(m_trampoline.unwrap().end(), inst->getBytes().begin(), inst->getBytes().end());

        // U.B. if we access data() before vector has any elements
        trampolineDelta = (int64_t)(m_trampoline.unwrap().data() - m_fnAddress);
        inst->setAddress(inst->getAddress() + trampolineDelta);

        if (inst->hasDisplacement() && inst->isDisplacementRelative() && !m_disassembler.isConditionalJump(*inst))
            inst->setRelativeDisplacement(inst->getDisplacement().Relative - trampolineDelta);
        m_disassembler.writeEncoding(*inst);
    }
    return trampolineDelta;
}

/**Builds a jump table given a vector of condition jump instructions. The jump table is
 * placed at the end of the trampoline and each jump table entry points to where the
 * condition jump did before it was moved to the trampoline.**/
template<typename Architecture, typename Disassembler>
void Detour<Architecture, Disassembler>::insertTrampolineJumpTable(
        const InstructionVector& conditionalJumpsToFix,
        const int64_t trampolineDelta) {

    for (auto& inst : conditionalJumpsToFix) {
        uint64_t intermediateJumpLoc = (uint64_t)m_trampoline.unwrap().data() + m_trampoline.unwrap().size();

        // Reset instructions address to it's original so we can find where it originally jumped too
        inst->setAddress(inst->getAddress() - trampolineDelta);
        InstructionVector intermediateJumpVec = m_archImpl.makePreferredJump(intermediateJumpLoc,
                                                                             inst->getDestination());
        inst->setAddress(inst->getAddress() + trampolineDelta);

        // Point the relative jmp to the intermediate long jump
        Instruction::Displacement disp = {0};
        disp.Relative = PLH::ADisassembler::calculateRelativeDisplacement<int32_t>(inst->getAddress(),
                                                                                   intermediateJumpLoc,
                                                                                   inst->size());
        inst->setRelativeDisplacement(disp.Relative);

        // Write the intermediate jump and the changed cond. jump
        for (auto jmpInst : intermediateJumpVec) {
            m_trampoline.unwrap().insert(m_trampoline.unwrap().end(),
                                         jmpInst->getBytes().begin(),
                                         jmpInst->getBytes().end());
        }
        m_disassembler.writeEncoding(*inst);
    }
}

template<typename Architecture, typename Disassembler>
Maybe<InstructionVector>
Detour<Architecture, Disassembler>::calcPrologueMinLength(const InstructionVector& functionInsts,
                                                          size_t& lengthWanted) {
    std::size_t                                    prologueLength = 0;
    std::vector<std::shared_ptr<PLH::Instruction>> instructionsInRange;

    for (auto inst : functionInsts) {
        if (prologueLength >= lengthWanted)
            break;

        //TODO: detect end of function better
        if (inst->getMnemonic() == "ret")
            break;

        prologueLength += inst->size();
        instructionsInRange.push_back(inst);
    }

    if (prologueLength >= lengthWanted) {
        lengthWanted = prologueLength;
        return std::move(instructionsInRange);
    }
    function_fail("Function too small, function is not of length >= " + std::to_string(lengthWanted));
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::unHook() {

}

template<typename Architecture, typename Disassembler>
HookType Detour<Architecture, Disassembler>::getType() {
    return m_archImpl.getType();
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::shouldMakePrologueJmpTable(const InstructionVector& functionInsts,
                                                                    size_t& overWrittenBytes) {
    assert(functionInsts.size() > 0);

    size_t walkedBytes = 0;
    for (const auto& inst : functionInsts) {
        // Walk only the section of prologue that will be overwritten
        if (walkedBytes >= overWrittenBytes)
            break;

        walkedBytes += inst->size();

        // If anything in that section is pointed to, we need a jump table
        if (inst->getChildren().size() > 0)
            return true;
    }
    assert(walkedBytes >= overWrittenBytes);

    // Cool nothing points back into prologue ezpz from here. (This is 99.99% of time).
    return false;
}

template<typename Architecture, typename Disassembler>
PLH::Maybe<InstructionVector>
Detour<Architecture, Disassembler>::insertPrologueJumpTable(const InstructionVector& functionInsts,
                                                            size_t& overWrittenBytes) {
    assert(functionInsts.size() > 0);
    typedef std::vector<std::shared_ptr<PLH::Instruction>> InstructionChildren;

    InstructionVector                      modifiedPrologue;
    std::map<uint8_t, InstructionChildren> jumpsToFix;

    bool jumpAbsolute = m_archImpl.minimumJumpType() == PLH::JmpType::Absolute;

    uint8_t tableEntries = 0;
    uint8_t tableSize    = 0;
    uint8_t walkedBytes  = 0;
    for (const auto& inst : functionInsts) {
        if (walkedBytes >= overWrittenBytes)
            break;

        walkedBytes += inst->size();

        // keep the instruction pointed at
        modifiedPrologue.push_back(inst);

        // end of function
        if (inst->getMnemonic() == "ret")
            break;

        if (inst->getChildren().size() <= 0)
            continue;

        /* if inst is pointed at, note to make a table entry
         * and remember who to point at that entry.*/
        jumpsToFix[tableEntries++] = inst->getChildren();

        /* expand prologue to hold the jump table entries. This
           is a recursive problem done iteratively. By expanding
           the prologue we may overwrite more instructions pointed
           at.*/
        tableSize += (m_archImpl.minimumPrologueLength() + (jumpAbsolute ? 0 : 8));
        overWrittenBytes += tableSize;
    }

    /* Make a place for indirect jumps if we need too. Should be +- 2Gb from prologue*/
    m_prologueJumpTable = std::move(m_archImpl.makeMemoryBuffer(m_fnAddress));
    try {
        m_prologueJumpTable.unwrap().reserve(tableSize);
    }catch (const PLH::AllocationFailure& ex) {
        function_fail("Unable to allocate space for indirect prologue table");
    }

    /* This may happen if we expand the prologue to hold jump table entries, but
     * we encounter function end before we encounter enough bytes for said entry.
     * In that case there is no room for the jump table, and we must fail.*/
    if (walkedBytes < overWrittenBytes)
        function_fail("Function does cyclic prologue jumps and is to small for jump table");

    //TODO: make this
    // we have the room for jump table, add N entries to end of prologue, and point saved children to entry
    for (uint8_t i = 0; i < tableEntries; i++) {
        InstructionVector jumpInstruction;
        if (jumpAbsolute) {
            //jumpInstruction = m_archImpl.makeMinimumJump(m_fnAddress, m_fnCallback);
        } else {
            //m_archImpl.setIndirectHolder((uint64_t)m_trampoline->data() + m_trampoline->size());
            //jumpInstruction = m_archImpl.makeMinimumJump(m_fnAddress, m_fnCallback);
        }
    }
}

template<typename Architecture, typename Disassembler>
void Detour<Architecture, Disassembler>::dbgPrintInstructionVec(const std::string& name,
                                                                const InstructionVector& instructionVector) {
    if (!m_debugSet)
        return;

    std::cout << name << std::endl;
    for (const auto& inst : instructionVector)
        std::cout << *inst << std::endl;
    std::cout << std::endl;
}
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
