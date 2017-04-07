//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP
#include <vector>
#include <memory>
#include "ErrorSystem.hpp"

class MemAllocator : public PLH::Errant
{
public:
    struct AllocImpl
    {
        uint8_t *AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size);
    };
private:
    std::vector<std::unique_ptr<uint8_t>> m_Caves;
};
#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP
