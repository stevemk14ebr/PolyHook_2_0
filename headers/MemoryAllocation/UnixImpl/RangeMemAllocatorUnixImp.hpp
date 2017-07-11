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
#include <string.h>
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
    AllocateMemory(const uint64_t MinAddress, const uint64_t MaxAddress,
                   const size_t Size, const PLH::ProtFlag Protections) const;

    size_t QueryPreferedAllocSize() const;

protected:
    void Deallocate(uint8_t* Buffer, const size_t Length) const;

    PLH::Maybe<PLH::AllocatedMemoryBlock>
    AllocateImp(const uint64_t AddressOfPage, const size_t Size, const int MapFlags,
                const PLH::ProtFlag Protections) const;

    std::vector<PLH::MemoryBlock> GetAllocatedVABlocks() const;

    std::vector<PLH::MemoryBlock> GetFreeVABlocks() const;
};
}
#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
