//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP
#include <vector>
#include <memory>
#include "ErrorSystem.hpp"
#include "Misc.hpp"
#include "Enums.hpp"
#include "MemoryBlock.hpp"

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
namespace PLH
{
    template<typename PlatformImp>
    class MemAllocator : private PlatformImp, public virtual PLH::Errant
    {
    public:
        uint8_t *AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections)
        {
            uint8_t* Cave = PlatformImp::AllocateMemory(MinAddress,MaxAddress, Size, Protections);
            if (Cave == nullptr || VerifyMemInRange(MinAddress, MaxAddress, (uint64_t) Cave)) {
                m_Caves.emplace_back(Cave);
            } else {
                SendError("Failed to allocate memory in range");
                return nullptr;
            }
            return Cave;
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
    protected:
        bool VerifyMemInRange(uint64_t MinAddress, uint64_t MaxAddress, uint64_t Needle);

        std::vector<std::unique_ptr<uint8_t>> m_Caves;
    };

    //[MinAddress, MaxAddress)
    template <typename PlatformImp>
    bool MemAllocator<PlatformImp>::VerifyMemInRange(uint64_t MinAddress, uint64_t MaxAddress, uint64_t Needle)
    {
        if (Needle >= MinAddress && Needle < MaxAddress)
            return true;
        return false;
    }
}

//Implementation instantiations
#include "UnixImpl/MemAllocatorUnix.hpp"
namespace PLH{
    using MemAllocatorU = PLH::MemAllocator<PLH::MemAllocatorUnix>;
}
#endif //POLYHOOK_2_0_MEMALLOCATOR_HPP

