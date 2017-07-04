//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_IHOOK_HPP
#define POLYHOOK_2_0_IHOOK_HPP

#include "src/ErrorSystem.hpp"
#include "src/ADisassembler.hpp"

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
    IHook() = default;

    IHook(IHook&& other) = default; //move
    IHook& operator=(IHook&& other) = default;//move assignment
    IHook(const IHook& other) = delete; //copy
    IHook& operator=(const IHook& other) = delete; //copy assignment
    virtual ~IHook() = default;

    virtual bool Hook() = 0;

    virtual bool UnHook() = 0;

    virtual HookType GetType() = 0;
};
}
#endif //POLYHOOK_2_0_IHOOK_HPP
