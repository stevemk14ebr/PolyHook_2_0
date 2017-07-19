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

    virtual bool Hook() override;

    virtual bool UnHook() override;

    virtual PLH::HookType GetType() override;

    template<typename T>
    T getOriginal() {
        return (T)&trampoline->front();
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

    uint64_t                    fnAddress;
    uint64_t                    fnCallback;
    bool                        hooked;
    std::unique_ptr<ArchBuffer> trampoline; //so that we can delay instantiation

    Architecture archImpl;
    Disassembler disassembler;
};


template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) :
        archImpl(), disassembler(archImpl.GetArchType()) {
    fnAddress  = hookAddress;
    fnCallback = callbackAddress;
    hooked     = false;
}

template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const char* hookAddress, const char* callbackAddress) :
        archImpl(), disassembler(archImpl.GetArchType()) {

    fnAddress  = (uint64_t)hookAddress;
    fnCallback = (uint64_t)callbackAddress;
    hooked     = false;
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::Hook() {

    // Allocate some memory near the callback for the trampoline
    auto bufMaybe = archImpl.AllocateMemory(fnCallback);
    if (!bufMaybe)
        return false;
    trampoline = std::move(bufMaybe).unwrap();

    /* Disassemble the prologue and find the instructions that will be overwritten by our jump.
     * Also simultaneously check that the function prologue is big enough for our jump*/
    InstructionVector instructions = disassembler.Disassemble(fnAddress, fnAddress, fnAddress + 100);
    if (instructions.size() == 0)
        return false;

    dbgPrintInstructionVec("Original function: ", instructions);

    // Certain jump types are better than others, see if we have room for the better one, otherwise fallback
    bool    doPreferredJmp = true;
    bool    jumpAbsolute   = archImpl.preferredJumpType() == PLH::JmpType::Absolute;
    uint8_t jumpLength     = archImpl.preferredPrologueLength();
    size_t  prologueLength = jumpLength;

    auto maybePrologueInstructions = calculatePrologueLength(instructions, prologueLength);
    if (!maybePrologueInstructions) {
        doPreferredJmp = false;
        jumpAbsolute   = archImpl.minimumJumpType() == PLH::JmpType::Absolute;
        jumpLength     = archImpl.minimumPrologueLength();
        prologueLength = jumpLength;

        maybePrologueInstructions = calculatePrologueLength(instructions, prologueLength);
    }

    if (!maybePrologueInstructions)
        return false;
    InstructionVector prologueInstructions = std::move(maybePrologueInstructions).unwrap();
    dbgPrintInstructionVec("Prologue: ", prologueInstructions);

    // Count # of entries that will be in the jump table
    InstructionVector conditionalJumpsToFix;
    for (auto         inst : prologueInstructions) {
        if (disassembler.isConditionalJump(*inst))
            conditionalJumpsToFix.push_back(inst);
    }

    /* reserve space for relocated prologue + jmp to fnAddress.Body + N jump table entries
     * + optional indirect location if our jump type is an indirect style (!Absolute).
     * DO NOT remove this reservation, without it the underlying vector could relocate the
     * trampoline without letting us know on a push_back or insert, and all our precious
     * fixups are out the window.*/
    size_t reserveSize = prologueLength +
                         jumpLength +
                         (conditionalJumpsToFix.size() * archImpl.preferredPrologueLength())
                         + 8; //8 for the optional destination holder

    trampoline->reserve(reserveSize);
    int64_t trampolineDelta = 0;

    /* Copy (truly copy, original are untouched) instructions from the prologue to the trampoline. Also fixup the various types of
       instructions that need to be fixed (RIP/EIP relative), excluding conditional jumps */
    for (auto& inst : prologueInstructions) {
        // Copy instruction into the trampoline (they will be malformed)
        trampoline->insert(trampoline->end(), inst->GetBytes().begin(), inst->GetBytes().end());

        // sadly we must do this in a loop, UB if we access data() before vector has any elements
        trampolineDelta = (int64_t)(trampoline->data() - fnAddress);
        inst->SetAddress(inst->GetAddress() + trampolineDelta);

        if (inst->HasDisplacement() && inst->IsDisplacementRelative() && !disassembler.isConditionalJump(*inst))
            inst->SetRelativeDisplacement(inst->GetDisplacement().Relative - trampolineDelta);
        disassembler.WriteEncoding(*inst);
    }

    // Insert the jmp to fnAddress.Body from the trampoline
    InstructionVector bodyJump = archImpl.makePreferredJump((uint64_t)trampoline->data() + trampoline->size(),
                                                            fnAddress + jumpLength);

    for (auto inst : bodyJump)
        trampoline->insert(trampoline->end(), inst->GetBytes().begin(), inst->GetBytes().end());

    // Build the jump table
    for (auto& inst : conditionalJumpsToFix) {
        uint64_t intermediateJumpLoc = (uint64_t)trampoline->data() + trampoline->size();

        // Reset instructions address to it's original so we can find where it original jumped too
        inst->SetAddress(inst->GetAddress() - trampolineDelta);
        InstructionVector intermediateJumpVec = archImpl.makePreferredJump(intermediateJumpLoc,
                                                                           inst->GetDestination());
        inst->SetAddress(inst->GetAddress() + trampolineDelta);

        // Point the relative jmp to the intermediate long jump
        PLH::Instruction::Displacement disp = {0};
        disp.Relative = PLH::ADisassembler::CalculateRelativeDisplacement<int32_t>(inst->GetAddress(),
                                                                                   intermediateJumpLoc,
                                                                                   inst->Size());
        inst->SetRelativeDisplacement(disp.Relative);

        // Write the intermediate jump and the changed cond. jump
        for (auto jmpInst : intermediateJumpVec) {
            trampoline->insert(trampoline->end(), jmpInst->GetBytes().begin(), jmpInst->GetBytes().end());
        }
        disassembler.WriteEncoding(*inst);
    }

    // Make the fnAddress's memory page writeable
    uint64_t fnAddressPage = (uint64_t)PLH::AlignDownwards((char*)fnAddress, getpagesize());

    PLH::MemoryProtector<PLH::UnixMemProtImp> memoryProtectorFn(fnAddressPage,
                                                                getpagesize(),
                                                                PLH::ProtFlag::R | PLH::ProtFlag::W | PLH::ProtFlag::X);
    if (!memoryProtectorFn.originalProt())
        return false;

    /* Overwrite the prologue with the jmp to the callback. We
     * also check if the jmp type we want to write is absolute or
     * indirect. If indirect the intermediate location is stored
     * at the end of the trampoline (past jump table)*/
    InstructionVector detourJump;
    if (doPreferredJmp) {
        detourJump = archImpl.makePreferredJump(fnAddress, fnCallback);
    } else {
        if (jumpAbsolute) {
            detourJump = archImpl.makeMinimumJump(fnAddress, fnCallback);
        } else {
            archImpl.setIndirectHolder((uint64_t)trampoline->data() + trampoline->size());
            detourJump = archImpl.makeMinimumJump(fnAddress, fnCallback);
        }
    }

    for (auto inst : detourJump)
        disassembler.WriteEncoding(*inst);

    // Nop the space between jmp and end of prologue
    std::memset((char*)(fnAddress + jumpLength), 0x90, prologueLength - jumpLength);

    if (m_debugSet) {
        std::cout << "fnAddress: " << std::hex << fnAddress << " fnCallback: " << fnCallback <<
                  " trampoline: " << (uint64_t)trampoline->data() << " delta: "
                  << trampolineDelta << std::dec << std::endl;

        InstructionVector trampolineInst = disassembler.Disassemble((uint64_t)trampoline->data(),
                                                                    (uint64_t)trampoline->data(),
                                                                    (uint64_t)trampoline->data() + trampoline->size());
        dbgPrintInstructionVec("Trampoline: ", trampolineInst);

        // Go a little past prologue to see if we corrupted anything
        InstructionVector newPrologueInst = disassembler.Disassemble(fnAddress,
                                                                     fnAddress,
                                                                     fnAddress + prologueLength + 10);
        dbgPrintInstructionVec("New Prologue: ", newPrologueInst);
    }

    /* If this happen the vector was somehow resized.
     * This would be very bad for us, since we manually
     * mutate instruction displacements. Therefore
     * moving the trampoline makes our fixups invalid.
     * Figure out why this happened or stuff blows up*/
    if(trampoline->capacity() != reserveSize) {
        assert(false);
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
     *                      Example jmp table (with an example prologue):
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
        if (inst->GetMnemonic() == "ret")
            break;

        prologueLength += inst->Size();
        instructionsInRange.push_back(inst);
    }

    lengthWanted = prologueLength;
    if (prologueLength >= lengthWanted)
        return std::move(instructionsInRange);
    function_fail("Function too small, function is not of length >= " + std::to_string(lengthWanted));
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::UnHook() {

}

template<typename Architecture, typename Disassembler>
PLH::HookType Detour<Architecture, Disassembler>::GetType() {
    return archImpl.GetType();
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
