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
#include "headers/Enums.hpp"
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
typedef std::map<uint8_t, InstructionVector> JumpTableMap;

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

    /**Walks the given vector of instructions and rounds up the prolEndOffset to smallest offset that won't split any
     * instructions that is also >= prolStartOffset. If end of function is encountered before this condition a failed
     * maybe is returned. Otherwise the instructions in the region functionInsts[0] to the adjusted prolEndOffset
     * are returned.**/
    PLH::Maybe<InstructionVector>
    calcPrologueMinLength(const InstructionVector& functionInsts, const size_t prolOvrwStartOffset,
                          size_t& prolOvrwEndOffset);

    
    PLH::Maybe<InstructionVector>
    insertPrologueJumpTable(const JumpTableMap& jumpTableMap,
                            const size_t prolTableStartOffset);

    PLH::Maybe<JumpTableMap, ErrorSeverityMsg> calcPrologueJumpTable(const InstructionVector& jumpTableMap,
                                                   size_t& prolOvrwStartOffset,
                                                   size_t& prolOvrwEndOffset);

    // TODO: make trampoline table function use JumpTable type
    void insertTrampolineJumpTable(const InstructionVector& conditionalJumpsToFix, const int64_t trampolineDelta);

    int64_t insertTrampolinePrologue(const InstructionVector& prologueInstructions);

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
};


template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) :
        m_archImpl(), m_disassembler(m_archImpl.GetArchType()) {
    assert(hookAddress != 0 && callbackAddress != 0);
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
    bool   jumpAbsolute            = m_archImpl.minimumJumpType() == PLH::JmpType::Absolute;
    size_t prologueOvrwStartOffset = m_archImpl.minimumPrologueLength();
    size_t prologueOvrwEndOffset   = prologueOvrwStartOffset;

    auto maybePrologueInstructions = calcPrologueMinLength(instructions,
                                                           prologueOvrwStartOffset,
                                                           prologueOvrwEndOffset);
    if (!maybePrologueInstructions) {
        sendError(maybePrologueInstructions.unwrapError());
        return false;
    }
    assert(prologueOvrwEndOffset >= prologueOvrwStartOffset);

    InstructionVector prologueInstructions = std::move(maybePrologueInstructions).unwrap();
    dbgPrintInstructionVec("Prologue: ", prologueInstructions);

    // at this point prolOvrwStartOffset points to the end of the jump
    const size_t prolJumpTableStartOffset = prologueOvrwStartOffset;
    PLH::Maybe<JumpTableMap, ErrorSeverityMsg> prolJumpTableMap = calcPrologueJumpTable(instructions, prologueOvrwStartOffset, prologueOvrwEndOffset);
    if(!prolJumpTableMap && prolJumpTableMap.unwrapError().m_severity != ErrorSeverity::Ok) {
        sendError(prolJumpTableMap.unwrapError().m_errorMsg);
        return false;
    }
    assert(prologueOvrwEndOffset >= prologueOvrwStartOffset);

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
    size_t reserveSize = prologueOvrwEndOffset +
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
                                                              m_fnAddress + m_archImpl.minimumPrologueLength());

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

    // insert prolJumpTable if appropriate
    if(prolJumpTableMap)
    {
        PLH::Maybe<InstructionVector> tableInsts = insertPrologueJumpTable(prolJumpTableMap.unwrap(), prolJumpTableStartOffset);
        if(tableInsts){
            for(const auto& inst : tableInsts.unwrap())
                m_disassembler.writeEncoding(*inst);
        }
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
    std::memset((char*)(m_fnAddress + prologueOvrwStartOffset),
                0x90,
                prologueOvrwEndOffset - prologueOvrwStartOffset);

    if (m_debugSet) {
        std::cout << "fnAddress: " << std::hex << m_fnAddress << " fnCallback: " << m_fnCallback <<
                  " trampoline: " << (uint64_t)m_trampoline.unwrap().data() << " delta: "
                  << trampolineDelta << std::dec << std::endl;

        InstructionVector trampolineInst = m_disassembler.disassemble((uint64_t)m_trampoline.unwrap().data(),
                                                                      (uint64_t)m_trampoline.unwrap().data(),
                                                                      (uint64_t)m_trampoline.unwrap().data() +
                                                                      m_trampoline.unwrap().size());
        dbgPrintInstructionVec("Trampoline: ", trampolineInst);

        // print the indirect holder
        std::stringstream ss;
        for(int i = 0; i < 8; i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned)m_trampoline.unwrap()[m_trampoline.unwrap().size() + i] << " ";
        std::cout << ss.str() << std::endl;

        // Go a little past prologue to see if we corrupted anything
        InstructionVector newPrologueInst = m_disassembler.disassemble(m_fnAddress,
                                                                       m_fnAddress,
                                                                       m_fnAddress + prologueOvrwEndOffset + 30);
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
                                                          const size_t prolOvrwStartOffset,
                                                          size_t& prolOvrwEndOffset) {
    std::size_t                                    prologueLength = 0;
    std::vector<std::shared_ptr<PLH::Instruction>> instructionsInRange;

    for (auto inst : functionInsts) {
        if (prologueLength >= prolOvrwStartOffset)
            break;

        //TODO: determine if more stringent tests needed
        if (inst->getMnemonic() == "ret")
            break;

        prologueLength += inst->size();
        instructionsInRange.push_back(inst);
    }

    if (prologueLength >= prolOvrwStartOffset) {
        prolOvrwEndOffset = prologueLength;
        return std::move(instructionsInRange);
    }
    function_fail("Function too small, function is not of length >= " + std::to_string(prolOvrwStartOffset));
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::unHook() {

}

template<typename Architecture, typename Disassembler>
HookType Detour<Architecture, Disassembler>::getType() {
    return m_archImpl.getType();
}

template<typename Architecture, typename Disassembler>
PLH::Maybe<InstructionVector>
Detour<Architecture, Disassembler>::insertPrologueJumpTable(const JumpTableMap& jumpTableMap,
                                                            const size_t prolTableStartOffset) {
    function_assert(jumpTableMap.size() > 0);
    function_assert(m_trampoline.isOk() && m_trampoline.unwrap().capacity() > 0);

    const bool jumpAbsolute = m_archImpl.minimumJumpType() == PLH::JmpType::Absolute;

    // Make a place for indirect jump holders. Should be +- 2Gb from prologue
    if (!jumpAbsolute) {
        m_prologueJumpTable = std::move(m_archImpl.makeMemoryBuffer(m_fnAddress));

        try {
            m_prologueJumpTable.unwrap().resize(jumpTableMap.size() * 8, 0xCC);
        }catch (const PLH::AllocationFailure& ex) {
            function_fail("Unable to allocate space for indirect prologue table");
        }
    }

    InstructionVector instructionsToWriteLater;

    // we have the room for jump table. Add N entries to end of prologue, and point saved children to entry
    for (uint8_t i = 0; i < jumpTableMap.size(); i++) {
        // calc offset between inst pointed at and prologue start
        uint64_t homeOffset       = jumpTableMap.at(i)[0]->getDestination() - m_fnAddress;
        uint64_t entryLocation    = m_fnAddress + prolTableStartOffset + (i * m_archImpl.minimumPrologueLength());
        uint64_t entryDestination = (uint64_t)m_trampoline.unwrap().data() + homeOffset; // moved prologue guaranteed to be same offset away

        InstructionVector jumpInstruction;
        if (jumpAbsolute) {
            jumpInstruction = m_archImpl.makeMinimumJump(entryLocation, entryDestination);
        } else {
            m_archImpl.setIndirectHolder((uint64_t)m_prologueJumpTable.unwrap().data() + (i * 8));
            jumpInstruction = m_archImpl.makeMinimumJump(entryLocation, entryDestination);
        }

        // write the table entries later
        instructionsToWriteLater.insert(instructionsToWriteLater.end(), jumpInstruction.begin(),
                                        jumpInstruction.end());

        // point children to the new entry
        for (auto& child : jumpTableMap.at(i)) {
            if (!child->hasDisplacement() || !child->isDisplacementRelative())
                continue;

            int64_t newRelativeDisp = PLH::ADisassembler::calculateRelativeDisplacement<int64_t>(child->getAddress(),
                                                                                                 entryLocation,
                                                                                                 child->size());
            child->setRelativeDisplacement(newRelativeDisp);

            // write them later
            instructionsToWriteLater.push_back(child);
        }
    }
    return instructionsToWriteLater;
}

template<typename Architecture, typename Disassembler>
PLH::Maybe<JumpTableMap, ErrorSeverityMsg> Detour<Architecture, Disassembler>::calcPrologueJumpTable(const InstructionVector& functionInsts,
                                                                                        size_t& prolOvrwStartOffset,
                                                                                        size_t& prolOvrwEndOffset){
    JumpTableMap tableMap;

    uint8_t tableEntries = 0;
    uint8_t tableSize    = 0;
    uint8_t walkedBytes  = 0;
    for (const auto& inst : functionInsts) {
        if (walkedBytes >= prolOvrwStartOffset)
            break;

        walkedBytes += inst->size();

        // end of function
        if (inst->getMnemonic() == "ret")
            break;

        /* does the current instruction go past any elements in our map.
         * If so then our jump table would be overwriting a jump, very bad.*/
        if(std::find_if(tableMap.begin(), tableMap.end(), [&](const auto& pair){
            for(const auto& mapInst : pair.second){
                if(inst->getAddress() >= mapInst->getAddress())
                    return true;
            }
            return false;
        }) != tableMap.end()){
            function_fail(ErrorSeverity::Important, "Function to small to make jump table");
        }

        if (inst->getChildren().empty())
            continue;

        /* if inst is pointed at, note to make a table entry
         * and remember who to point at that entry.*/
        tableMap[tableEntries++] = inst->getChildren();

        /* expand prologue to hold the jump table entries. This
           is a recursive problem done iteratively. By expanding
           the prologue we may overwrite more instructions pointed
           at.*/
        tableSize += m_archImpl.minimumPrologueLength();
        prolOvrwStartOffset += tableSize;
    }

    /*TODO: fix case where children pointing to intermediate jump can
     get overwritten by jump table*/

    // no work
    if(tableEntries == 0)
        function_fail(ErrorSeverity::Ok, "No table needed");

    // round up end pointer to not split instrs
    if (walkedBytes >= prolOvrwStartOffset) {
        prolOvrwEndOffset = walkedBytes;
    }else{
        function_fail(ErrorSeverity::Important, "Function does cyclic prologue jumps and is to small for jump table");
    }
    return tableMap;
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
