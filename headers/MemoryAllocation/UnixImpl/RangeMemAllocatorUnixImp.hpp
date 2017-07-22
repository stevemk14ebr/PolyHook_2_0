//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#define POLYHOOK_2_0_MEMALLOCATORUNIX_HPP


#include "headers/MemoryAllocation/MemoryBlock.hpp"
#include "headers/MemoryAllocation/AllocatedMemoryBlock.hpp"
#include "headers/Maybe.hpp"

#include <sys/mman.h>
#include <sys/types.h>

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <vector>

namespace PLH {
/******************************************************************************************************************
 ** This is the unix implementation for the ARangeMemoryAllocator class. It reads the maps file of the current
 ** process to find currently allocated chunks of VirtualMemory. It then scans the returned list of blocks to find
 ** gaps that can be allocated into. Only gaps that are within the range of min and max are valid candidates. It
 ** properly handles cases where the valid min and max range overlap with potentially valid allocation blocks. Once
 ** it finds a valid block it mmap's this region, wraps the pointer in a shared_ptr with a custom deleter, and wraps
 ** that into an AllocatedMemoryBlock
 *****************************************************************************************************************/
class RangeMemAllocatorUnixImp
{
public:
    PLH::Maybe<PLH::AllocatedMemoryBlock>
    allocateMemory(const uint64_t minAddress, const uint64_t maxAddress,
                   const size_t size, const PLH::ProtFlag protections) const;

    size_t queryPrefferedAllocSize() const;

protected:
    void deallocate(char* buffer, const size_t length) const;

    PLH::Maybe<PLH::AllocatedMemoryBlock>
    allocateImp(const uint64_t addressOfPage, const size_t size, const int mapFlags,
                const PLH::ProtFlag protections) const;

    std::vector<PLH::MemoryBlock> getAllocatedVABlocks() const;

    std::vector<PLH::MemoryBlock> getFreeVABlocks() const;
};
}
#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
