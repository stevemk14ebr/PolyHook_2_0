//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X86DETOUR_HPP
#define POLYHOOK_2_X86DETOUR_HPP

#include "headers/Maybe.hpp"

#include <vector>
#include <headers/IHook.hpp>

namespace PLH {

class x86DetourImp
{
public:
    typedef std::vector<uint8_t> DetourBuffer;

    PLH::Maybe<DetourBuffer> AllocateMemory(const uint64_t Hint);

    PLH::HookType GetType() const;

    PLH::Mode GetArchType() const;

private:

};
}
#endif //POLYHOOK_2_X86DETOUR_HPP
