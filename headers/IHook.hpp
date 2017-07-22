//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_IHOOK_HPP
#define POLYHOOK_2_0_IHOOK_HPP

#include "headers/ErrorSystem.hpp"
#include "headers/ADisassembler.hpp"

namespace PLH {
enum class HookType
{
    X86Detour,
    X64Detour,
    UNKNOWN
#if(ARCH_WIN)
    ,VFuncSwap,
    VFuncDetour,
    VTableSwap,
    IAT,
    VEH,
#endif
};

class IHook : public PLH::Errant
{
public:
    IHook() {
        m_debugSet = false;
    }

    IHook(IHook&& other) = default; //move
    IHook& operator=(IHook&& other) = default;//move assignment
    IHook(const IHook& other) = delete; //copy
    IHook& operator=(const IHook& other) = delete; //copy assignment
    virtual ~IHook() = default;

    virtual bool hook() = 0;

    virtual bool unHook() = 0;

    virtual HookType getType() = 0;

    virtual void setDebug(const bool state) {
        m_debugSet = state;
    }

protected:
    bool m_debugSet;
};
}
#endif //POLYHOOK_2_0_IHOOK_HPP
