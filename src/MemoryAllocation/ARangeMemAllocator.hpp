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
#include <iostream>

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
namespace PLH
{
    template<typename PlatformImp>
    class ARangeMemAllocator : private PlatformImp, public virtual PLH::Errant
    {
    public:
        std::shared_ptr<uint8_t> AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections)
        {
            uint8_t* Tmp = PlatformImp::AllocateMemory(MinAddress,MaxAddress, Size, Protections);
            if(Tmp != nullptr && VerifyMemInRange(MinAddress,MaxAddress,(uint64_t)Tmp))
            {
                //Custom deleter
                std::shared_ptr<uint8_t> Cave(Tmp,[=](uint8_t* Buffer){
                    Deallocate(Buffer, Size);
                });
                m_Caves.push_back(Cave);
                return Cave;
            }
            return std::shared_ptr<uint8_t>();
        }

        int TranslateProtection(ProtFlag flags)
        {
            return PlatformImp::TranslateProtection(flags);
        }

        std::vector<PLH::MemoryBlock> GetAllocatedVABlocks()
        {
            return PlatformImp::GetAllocatedVABlocks();
        }

        std::vector<PLH::MemoryBlock> GetFreeVABlocks()
        {
            return PlatformImp::GetFreeVABlocks();
        }

        std::vector<std::shared_ptr<uint8_t>> GetAllocatedCaves()
        {
            return m_Caves;
        }
    protected:
        void Deallocate(uint8_t *Buffer, size_t Length)
        {
            return PlatformImp::Deallocate(Buffer,Length);
        }

        //[MinAddress, MaxAddress)
        bool VerifyMemInRange(uint64_t MinAddress, uint64_t MaxAddress, uint64_t Needle)
        {
            if (Needle >= MinAddress && Needle < MaxAddress)
                return true;
            return false;
        }
        std::vector<std::shared_ptr<uint8_t>> m_Caves;
    };
}

//Implementation instantiations
#include "UnixImpl/RangeMemAllocatorUnixImp.hpp"
namespace PLH{
    using MemAllocatorUnix = PLH::ARangeMemAllocator<PLH::RangeMemAllocatorUnixImp>;
}
#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP

