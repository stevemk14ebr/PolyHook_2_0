//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include "headers/Maybe.hpp"
#include "headers/IHook.hpp"

#include <memory>
#include <vector>

namespace PLH {

class x86DetourImp
{
public:
    typedef std::vector<uint8_t> DetourBuffer;

    PLH::Maybe<DetourBuffer> AllocateMemory(const uint64_t Hint);

    PLH::HookType GetType() const;

    PLH::Mode GetArchType() const;

    uint8_t minimumPrologueLength() const;

    uint8_t preferedPrologueLength() const;

    std::shared_ptr<PLH::Instruction> makeMinimumSizeJump(const uint64_t address, const uint64_t destination) const;

    std::shared_ptr<PLH::Instruction> makePreferedSizeJump(const uint64_t address, const uint64_t destination) const;
private:

};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
