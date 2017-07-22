//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP

#include "headers/ErrorSystem.hpp"
#include "headers/Misc.hpp"
#include "headers/Enums.hpp"
#include "headers/Maybe.hpp"
#include "headers/MemoryAllocation/MemoryBlock.hpp"
#include "headers/MemoryAllocation/AllocatedMemoryBlock.hpp"

#include <vector>
#include <memory>
#include <iostream>
#include <algorithm>

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
namespace PLH {
/*******************************************************************************************************
 ** This class is a generic (abstract-ish hence 'A') wrapper around the platform specific
 ** implementation of allocating blocks of memory within specific ranges of virtual memory.
 ** It is given minimum and maximum ranges of memory that are acceptable to allocate within
 ** and then stores the blocks of memory that are allocated for use later.
 ********************************************************************************************************/
template<typename PlatformImp>
class ARangAllocator : private PlatformImp
{
public:
    PLH::Maybe<PLH::AllocatedMemoryBlock>
    allocateMemory(uint64_t minAddress, uint64_t maxAddress, size_t size, ProtFlag protections) {
        //TO-DO: Add call to Verify Mem in range
        auto Block = PlatformImp::allocateMemory(minAddress, maxAddress, size, protections);
        if (Block &&
            verifyMemInRange(minAddress, maxAddress, Block.unwrap().getDescription().getStart()) &&
            verifyMemInRange(minAddress, maxAddress, Block.unwrap().getDescription().getEnd())) {
            m_allocatedBlocks.push_back(Block.unwrap());
        }
        return Block;
    }

    void deallocateMemory(const AllocatedMemoryBlock& block) {
        m_allocatedBlocks.erase(std::remove(m_allocatedBlocks.begin(), m_allocatedBlocks.end(),
                                            block), m_allocatedBlocks.end());
    }

    //MemoryBlock because it's not an allocated region 'we' allocated
    std::vector<PLH::MemoryBlock> getAllocatedVABlocks() const {
        return PlatformImp::getAllocatedVABlocks();
    }

    std::vector<PLH::MemoryBlock> getFreeVABlocks() const {
        return PlatformImp::getFreeVABlocks();
    }

    std::vector<PLH::AllocatedMemoryBlock> getAllocatedBlocks() {
        return m_allocatedBlocks;
    }

    size_t queryPrefferedAllocSize() {
        return PlatformImp::queryPrefferedAllocSize();
    }

protected:
    //[MinAddress, MaxAddress)
    bool verifyMemInRange(uint64_t minAddress, uint64_t maxAddress, uint64_t needle) const {
        return needle >= minAddress && needle < maxAddress;
    }

    std::vector<PLH::AllocatedMemoryBlock> m_allocatedBlocks;
};
}

//Implementation instantiations
#include "UnixImpl/RangeMemAllocatorUnixImp.hpp"

namespace PLH {
using MemAllocatorUnix = PLH::ARangAllocator<PLH::RangeMemAllocatorUnixImp>;
}
#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP

