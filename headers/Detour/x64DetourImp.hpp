//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X64DETOURIMPL_HPP
#define POLYHOOK_2_X64DETOURIMPL_HPP


#include "headers/Enums.hpp"
#include "headers/Instruction.hpp"
#include <sstream>

namespace PLH {

class x64DetourImp
{
public:
    uint8_t* makeMemoryBuffer(const uint64_t hint);

    HookType getType() const;

    Mode getArchType() const;

    insts_t makeMinimumJump(const uint64_t address, const uint64_t destination) const;

    insts_t makePreferredJump(const uint64_t address, const uint64_t destination) const;

private:
 
};
}
#endif //POLYHOOK_2_X64DETOURIMPL_HPP
