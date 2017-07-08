//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_ADETOUR_HPP
#define POLYHOOK_2_0_ADETOUR_HPP

#include "headers/CapstoneDisassembler.hpp"
#include "headers/Detour/x64DetourImp.hpp"
#include "headers/Detour/x86DetourImp.hpp"

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
    uint64_t   fnAddress;
    uint64_t   fnCallback;
    bool       hooked;
    ArchBuffer detourBuffer;

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

    //Allocate some memory near the callback for the trampoline
    auto bufMaybe = archImpl.AllocateMemory(fnCallback);
    if(!bufMaybe)
        return false;
    ArchBuffer buf = std::move(bufMaybe).unwrap();

    std::vector<std::shared_ptr<PLH::Instruction>> instructions = disassembler.Disassemble(fnAddress, fnAddress, fnAddress + 100);
    if(instructions.size() == 0)
        return false;

    std::size_t prologueLength = 0;
    for(auto inst : instructions)
    {
        if(prologueLength >= archImpl.minimumPrologueLength())
            break;

        prologueLength += inst->Size();
        
        //TODO: detect end of function
    }

    return true;
}

template<typename Architecture, typename Disassembler>
bool Detour<Architecture, Disassembler>::UnHook() {

}

template<typename Architecture, typename Disassembler>
PLH::HookType Detour<Architecture, Disassembler>::GetType() {
    return archImpl.GetType();
}
}
#endif //POLYHOOK_2_0_ADETOUR_HPP
