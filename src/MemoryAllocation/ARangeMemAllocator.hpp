//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP
#include <vector>
#include <memory>
#include "../ErrorSystem.hpp"
#include "../Misc.hpp"
#include "../Enums.hpp"
#include "MemoryBlock.hpp"
#include "AllocatedMemoryBlock.hpp"
#include <iostream>
#include <algorithm>

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
namespace PLH{
    /*******************************************************************************************************
     ** This class is a generic (abstract-ish hence 'A') wrapper around the platform specific
     ** implementation of allocating blocks of memory within specific ranges of virtual memory.
     ** It is given minimum and maximum ranges of memory that are acceptable to allocate within
     ** and then stores the blocks of memory that are allocated for use later.
     ********************************************************************************************************/
    template<typename PlatformImp>
    class ARangeMemAllocator : private PlatformImp
    {
    public:
        PLH::AllocatedMemoryBlock AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections)
        {
            //TO-DO: Add call to Verify Mem in range
            AllocatedMemoryBlock Block = PlatformImp::AllocateMemory(MinAddress,MaxAddress, Size, Protections);
            if(Block.GetParentBlock() != nullptr) {
                m_AllocatedBlocks.push_back(Block);
                return Block;
            }else{
                //TO-DO: Handle this case properly
                throw PLH::AllocationFailure();
            }
        }

        void DeallocateMemory(const AllocatedMemoryBlock& Block)
        {
           m_AllocatedBlocks.erase(std::remove(m_AllocatedBlocks.begin(),m_AllocatedBlocks.end(),
                         Block), m_AllocatedBlocks.end());
        }

        int TranslateProtection(const ProtFlag flags) const
        {
            return PlatformImp::TranslateProtection(flags);
        }

        //MemoryBlock because it's not an allocated region 'we' allocated
        std::vector<PLH::MemoryBlock> GetAllocatedVABlocks() const
        {
            return PlatformImp::GetAllocatedVABlocks();
        }

        std::vector<PLH::MemoryBlock> GetFreeVABlocks() const
        {
            return PlatformImp::GetFreeVABlocks();
        }

        std::vector<PLH::AllocatedMemoryBlock> GetAllocatedBlocks()
        {
            return m_AllocatedBlocks;
        }
    protected:
        //[MinAddress, MaxAddress)
        bool VerifyMemInRange(uint64_t MinAddress, uint64_t MaxAddress, uint64_t Needle)
        {
            if (Needle >= MinAddress && Needle < MaxAddress)
                return true;
            return false;
        }
        std::vector<PLH::AllocatedMemoryBlock> m_AllocatedBlocks;
    };
}

//Implementation instantiations
#include "UnixImpl/RangeMemAllocatorUnixImp.hpp"
namespace PLH{
    using MemAllocatorUnix = PLH::ARangeMemAllocator<PLH::RangeMemAllocatorUnixImp>;
}
#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP

