//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include "headers/CapstoneDisassembler.hpp"
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Detour/x86DetourImp.hpp"
#include "headers/Maybe.hpp"

/**All of these methods must be transactional. That
 * is to say that if a function fails it will completely
 * restore any external and internal state to the same
 * it was when the function began.
 **/
namespace PLH {

template<typename Architecture, typename Disassembler = PLH::CapstoneDisassembler>
class Detour : public PLH::IHook
{
public:
    typedef typename Architecture::DetourBuffer ArchBuffer;

    Detour(const uint64_t fnAddress, const uint64_t fnCallback);

    Detour(const uint8_t* fnAddress, const uint8_t* fnCallback);

    virtual bool Hook() override;

    virtual bool UnHook() override;

    virtual PLH::HookType GetType() override;

private:
    typedef std::vector<std::shared_ptr<PLH::Instruction>> InstructionVector;

    /**Walks the given prologue instructions and checks if the length is >= lengthWanted. If the prologue
     * is of the needed length it returns a vector of instruction that includes all instruction from the start up to
     * and including the last instruction giving the needed length. **/
    PLH::Maybe<InstructionVector> calculatePrologueLength(const InstructionVector& functionInsts, const uint8_t lengthWanted);

    void addJumpTableEntry(ArchBuffer& trampoline,PLH::Instruction& instruction);

    uint64_t   fnAddress;
    uint64_t   fnCallback;
    bool       hooked;
    ArchBuffer trampoline;

    Architecture archImpl;
    Disassembler disassembler;
};


template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint64_t hookAddress, const uint64_t callbackAddress) :
        archImpl(), disassembler(archImpl.GetArchType()) {
    fnAddress = hookAddress;
    fnCallback = callbackAddress;
    hooked          = false;
}

template<typename Architecture, typename Disassembler>
Detour<Architecture, Disassembler>::Detour(const uint8_t* hookAddress, const uint8_t* callbackAddress) :
        archImpl(), disassembler(archImpl.GetArchType()) {

    fnAddress = (uint64_t)hookAddress;
    fnCallback = (uint64_t)callbackAddress;
    hooked          = false;
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::Hook() {

    // Allocate some memory near the callback for the trampoline
    auto bufMaybe = archImpl.AllocateMemory(fnCallback);
    if(!bufMaybe)
        return false;
    trampoline = std::move(bufMaybe).unwrap();

    /* Disassemble the prologue and find the instructions that will be overwritten by our jump.
     * Also simultaneously check that the function prologue is big enough for our jump*/
    InstructionVector instructions = disassembler.Disassemble(fnAddress, fnAddress, fnAddress + 100);
    if(instructions.size() == 0)
        return false;

    // Certain jump types are better than others, see if we have room for the better one, otherwise fallback
    auto maybeInstructionsToMove = calculatePrologueLength(instructions, archImpl.preferedPrologueLength());
    if(!maybeInstructionsToMove)
        maybeInstructionsToMove = calculatePrologueLength(instructions, archImpl.minimumPrologueLength());

    if(!maybeInstructionsToMove)
        return false;

    /* Copy instructions in the prologue to the trampoline. Also fixup the various types of
     instructions that need to be fixed (RIP/EIP relative insts + cond jumps) */
    InstructionVector conditionalJumpsToFix;
    InstructionVector instructionsToMove = std::move(maybeInstructionsToMove).unwrap();

    std::int64_t trampolineDelta = ((uint64_t)&trampoline[0]) - fnAddress;
    for(auto inst : instructionsToMove)
    {
        inst->SetAddress(inst->GetAddress() + trampolineDelta);

        /* Conditional jumps are pointed to the jump table. We have to
         * delay this however because we don't know how long the trampoline
         * will be, and the jump table is inserted at the end. Rather than
         * over-estimate space and waste trampoline memory space in the long term,
         * we store these instructions in a vector and waste memory in the short term.*/
        if(disassembler.isConditionalJump(*inst)) {
            conditionalJumpsToFix.push_back(inst);
        }else{
            if(inst->HasDisplacement() && inst->IsDisplacementRelative())
                inst->SetRelativeDisplacement(inst->GetDisplacement().Relative + trampolineDelta);
        }
        // Copy instruction into the trampoline
        trampoline.insert(trampoline.end(), inst->GetBytes().begin(), inst->GetBytes().end());
    }



    return true;
}

template<typename Architecture, typename Disassembler>
PLH::Maybe<typename PLH::Detour<Architecture, Disassembler>::InstructionVector>
    Detour<Architecture, Disassembler>::calculatePrologueLength(const InstructionVector& functionInsts,
                                                                const uint8_t lengthWanted) {
    std::size_t prologueLength = 0;
    std::vector<std::shared_ptr<PLH::Instruction>> instructionsInRange;
    for(auto inst : functionInsts)
    {
        if(prologueLength >= lengthWanted)
            break;

        //TODO: detect end of function better (will currently fail on small functions)
        if(inst->GetMnemonic() == "ret")
            break;

        prologueLength += inst->Size();
        instructionsInRange.push_back(inst);
    }

    if(prologueLength >= lengthWanted)
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
void Detour<Architecture, Disassembler>::addJumpTableEntry(ArchBuffer& trampoline, PLH::Instruction& instruction) {

}
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
