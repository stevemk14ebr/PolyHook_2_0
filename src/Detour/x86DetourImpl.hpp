//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include "src/Maybe.hpp"

#include <vector>
#include <src/IHook.hpp>

class x86DetourImpl
{
public:
    typedef std::vector<uint8_t> DetourBuffer;

    PLH::Maybe<DetourBuffer> AllocateMemory(const uint64_t Hint);

    PLH::HookType GetType() const;
private:

};

PLH::Maybe<DetourBuffer> x86DetourImpl::AllocateMemory(const uint64_t Hint) {
    return DetourBuffer(); //any memory location will do for x86
}

PLH::HookType x86DetourImpl::GetType() const {
    return PLH::HookType::X86Detour;
}

#endif //POLYHOOK_2_X86DETOUR_HPP
