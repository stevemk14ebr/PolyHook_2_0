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
namespace PLH
{
    //unsafe enum by design to allow binary OR
    enum ProtFlag : std::uint8_t
    {
        X = 1 << 0,
        R = 1 << 1,
        W = 1 << 2,
        NONE = 1<< 3
    };

    bool operator&(ProtFlag lhs, ProtFlag rhs)
    {
        return static_cast<std::uint8_t>(lhs) &
               static_cast<std::uint8_t>(rhs);
    }

    ProtFlag operator|(ProtFlag lhs, ProtFlag rhs)
    {
        return static_cast<ProtFlag >(
                static_cast<std::uint8_t>(lhs) |
               static_cast<std::uint8_t>(rhs));
    }

    template<typename PlatformImp>
    class MemAllocator : private PlatformImp, public PLH::Errant
    {
    public:
        uint8_t *AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections)
        {
            uint8_t* Cave = PlatformImp::AllocateMemory(MinAddress,MaxAddress, Size, Protections);
            if (VerifyMemInRange(MinAddress, MaxAddress, (uint64_t) Cave)) {
                m_Caves.emplace_back(Cave);
            } else {
                this->SendError("Failed to allocate memory in range");
            }
            return Cave;
        }

        int TranslateProtection(ProtFlag flags)
        {
            return PlatformImp::TranslateProtection(flags);
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

