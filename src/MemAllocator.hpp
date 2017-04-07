//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP
#include <vector>
#include <memory>
#include "ErrorSystem.hpp"
#include "Misc.hpp"

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
class MemAllocator final : public PLH::Errant
{
public:
    //unsafe enum by design to allow binary OR
    enum ProtFlag{
        X,
        R,
        W,
        NONE
    };
    template<PLH::Platform platform>
    uint8_t *AllocateMemory<platform>(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections) {};
private:
    std::vector<std::unique_ptr<uint8_t>> m_Caves;
};

#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP
