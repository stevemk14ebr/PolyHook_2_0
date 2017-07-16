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
    typedef std::vector<uint8_t>                           DetourBuffer;
    typedef std::vector<std::shared_ptr<PLH::Instruction>> InstructionVector;

    PLH::Maybe<std::unique_ptr<DetourBuffer>> AllocateMemory(const uint64_t Hint);

    PLH::HookType GetType() const;

    PLH::Mode GetArchType() const;

    uint8_t minimumPrologueLength() const;

    uint8_t preferredPrologueLength() const;

    JmpType minimumJumpType() const;

    JmpType preferredJumpType() const;

    void setIndirectHolder(const uint64_t holderAddress);

    InstructionVector makeMinimumJump(const uint64_t address, const uint64_t destination) const;

    InstructionVector makePreferredJump(const uint64_t address, const uint64_t destination) const;

private:

};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
