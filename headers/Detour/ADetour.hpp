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
        return (T)&m_trampoline->front();
    }

private:
    /*  These are shared_ptrs because the can point to each other. Internally PLH::Instruction's
        store non-owning "child" pointers. If they lived on the stack the logic to do that would be
        much more complicated.*/
    typedef std::vector<std::shared_ptr<PLH::Instruction>> InstructionVector;

    /**Walks the given prologue instructions and checks if the length is >= lengthWanted. If the prologue
     * is of the needed length it returns a vector of instruction that includes all instruction from the start up to
     * and including the last instruction giving the needed length. The lengthWanted parameter is set to the
     * size (in bytes) of the returned InstructionVector, this vector's size is the smallest prologue length that
     * is >= lengthWanted and doesn't split any instructions**/
    PLH::Maybe<InstructionVector>
    calculatePrologueLength(const InstructionVector& functionInsts, size_t& lengthWanted);

    void dbgPrintInstructionVec(const std::string& name, const InstructionVector& instructionVector);

    uint64_t                    m_fnAddress;
    uint64_t                    m_fnCallback;
    bool                        m_hooked;
    std::unique_ptr<ArchBuffer> m_trampoline; //so that we can delay instantiation

    Architecture m_archImpl;
    Disassembler m_disassembler;

    void insertTrampolineJumpTable(const InstructionVector& conditionalJumpsToFix,const int64_t trampolineDelta);
    int64_t insertTrampolinePrologue(const InstructionVector& prologueInstructions);
};


template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) :
        m_archImpl(), m_disassembler(m_archImpl.GetArchType()) {
    m_fnAddress  = hookAddress;
    m_fnCallback = callbackAddress;
    m_hooked     = false;
}

template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const char* hookAddress, const char* callbackAddress) :
        m_archImpl(), m_disassembler(m_archImpl.getArchType()) {

    m_fnAddress  = (uint64_t)hookAddress;
    m_fnCallback = (uint64_t)callbackAddress;
    m_hooked     = false;
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::hook() {

    // Allocate some memory near the callback for the trampoline
    auto bufMaybe = m_archImpl.allocateMemory(m_fnCallback);
    if (!bufMaybe) {
        sendError("Failed to allocate trampoline");
        return false;
    }

    m_trampoline = std::move(bufMaybe).unwrap();

    // disassemble the function to hook
    InstructionVector instructions = m_disassembler.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100);
    if (instructions.size() == 0) {
        sendError("Disassembler unable to decode any valid instructions for given fnAddress");
        return false;
    }

    dbgPrintInstructionVec("Original function: ", instructions);

    // Always do the smallest jump to avoid extra complexities
    bool jumpAbsolute   = m_archImpl.minimumJumpType() == PLH::JmpType::Absolute;
    uint8_t jumpLength     = m_archImpl.minimumPrologueLength();
    size_t prologueLength = jumpLength;

    auto maybePrologueInstructions = calculatePrologueLength(instructions, prologueLength);
    if (!maybePrologueInstructions) {
        sendError(maybePrologueInstructions.unwrapError());
        return false;
    }

    InstructionVector prologueInstructions = std::move(maybePrologueInstructions).unwrap();
    dbgPrintInstructionVec("Prologue: ", prologueInstructions);

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
    m_trampoline->reserve(reserveSize);

    int64_t trampolineDelta = insertTrampolinePrologue(prologueInstructions);

    // Insert the jmp to fnAddress.Body from the trampoline
    InstructionVector bodyJump = m_archImpl.makePreferredJump((uint64_t)m_trampoline->data() + m_trampoline->size(),
                                                              m_fnAddress + jumpLength);

    for (const auto& inst : bodyJump)
        m_trampoline->insert(m_trampoline->end(), inst->getBytes().begin(), inst->getBytes().end());

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
        m_archImpl.setIndirectHolder((uint64_t)m_trampoline->data() + m_trampoline->size());
        detourJump = m_archImpl.makeMinimumJump(m_fnAddress, m_fnCallback);
    }

    for (const auto& inst : detourJump)
        m_disassembler.writeEncoding(*inst);

    // Nop the space between jmp and end of prologue
    std::memset((char*)(m_fnAddress + jumpLength), 0x90, prologueLength - jumpLength);

    if (m_debugSet) {
        std::cout << "fnAddress: " << std::hex << m_fnAddress << " fnCallback: " << m_fnCallback <<
                  " trampoline: " << (uint64_t)m_trampoline->data() << " delta: "
                  << trampolineDelta << std::dec << std::endl;

        InstructionVector trampolineInst = m_disassembler.disassemble((uint64_t)m_trampoline->data(),
                                                                      (uint64_t)m_trampoline->data(),
                                                                      (uint64_t)m_trampoline->data() +
                                                                      m_trampoline->size());
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
    if (m_trampoline->capacity() != reserveSize) {
        assert(false);
        sendError("Internal Error: Trampoline vector unexpectedly relocated");
        return false;
    }

    return true;

    /** Before Hook:                                                After hook:
     *
     * --------fnAddress--------                                    --------fnAddress--------
     * |    prologue           |                                   |    jmp fnCallback      | <- this may be an indirect jmp
     * |    ...body...         |      ----> Converted into ---->   |    ...body...          |  if it is, it reads the final
     * |    ret                |                                   |    ret                 |  dest from end of trampoline (optional indirect loc)
     * -------------------------                                   --------------------------
     *
     *                               Created during hooking:
     *                              --------Trampoline--------
     *                              |     prologue            | Executes fnAddress's prologue (we overwrote it with jmp)
     *                              |     jmp fnAddress.body  | Jmp back to first address after the overwritten prologue
     *                              |  ...jump table...       | Long jmp table that short jmps in prologue point to
     *                              |  optional indirect loc  | may or may not exist depending on jmp type we used
     *                              --------------------------
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
int64_t Detour<Architecture, Disassembler>::insertTrampolinePrologue(
        const typename Detour<Architecture, Disassembler>::InstructionVector& prologueInstructions) {

    int64_t trampolineDelta = 0;
    for (auto& inst : prologueInstructions) {
        // Copy instruction into the trampoline (they will be malformed)
        m_trampoline->insert(m_trampoline->end(), inst->getBytes().begin(), inst->getBytes().end());

        // U.B. if we access data() before vector has any elements
        trampolineDelta = (int64_t)(m_trampoline->data() - m_fnAddress);
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
        const typename Detour<Architecture, Disassembler>::InstructionVector& conditionalJumpsToFix,
        const int64_t trampolineDelta){

    for (auto& inst : conditionalJumpsToFix) {
        uint64_t intermediateJumpLoc = (uint64_t)m_trampoline->data() + m_trampoline->size();

        // Reset instructions address to it's original so we can find where it original jumped too
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
            m_trampoline->insert(m_trampoline->end(), jmpInst->getBytes().begin(), jmpInst->getBytes().end());
        }
        m_disassembler.writeEncoding(*inst);
    }
}

template<typename Architecture, typename Disassembler>
PLH::Maybe<typename PLH::Detour<Architecture, Disassembler>::InstructionVector>
Detour<Architecture, Disassembler>::calculatePrologueLength(const InstructionVector& functionInsts,
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

    lengthWanted = prologueLength;
    if (prologueLength >= lengthWanted)
        return std::move(instructionsInRange);
    function_fail("Function too small, function is not of length >= " + std::to_string(lengthWanted));
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::unHook() {

}

template<typename Architecture, typename Disassembler>
PLH::HookType Detour<Architecture, Disassembler>::getType() {
    return m_archImpl.getType();
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
