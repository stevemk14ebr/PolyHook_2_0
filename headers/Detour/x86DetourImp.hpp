//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include "headers/IHook.hpp"
#include "headers/Instruction.hpp"
#include <vector>
#include <sstream>

namespace PLH {

class x86DetourImp
{
public:
    HookType getType() const;

    Mode getArchType() const;

    insts_t makeMinimumJump(const uint64_t address, const uint64_t destination) const;

    insts_t makePreferredJump(const uint64_t address, const uint64_t destination) const;

private:

};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
