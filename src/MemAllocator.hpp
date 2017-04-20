//
// Created by steve on 4/5/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATOR_HPP
#define POLYHOOK_2_0_MEMALLOCATOR_HPP
#include <vector>
#include <memory>
#include "ErrorSystem.hpp"
#include "Misc.hpp"
#include <inttypes.h>

//http://altdevblog.com/2011/06/27/platform-abstraction-with-cpp-templates/
namespace PLH
{
    //unsafe enum by design to allow binary OR
    enum ProtFlag : std::uint8_t
    {
        UNSET = 0, //the value meaning no protection is set
        X = 1 << 1,
        R = 1 << 2,
        W = 1 << 3,
        S = 1 << 4,
        P = 1 << 5,
        NONE = 1 << 6 //The flag meaning PROT_UNSET
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

    std::string ProtFlagToString(PLH::ProtFlag flags)
    {
        std::string s = "";
        if(flags == PLH::ProtFlag::UNSET) {
            s += "UNSET";
            return s;
        }

        if (flags & PLH::ProtFlag::X)
            s += "x";
        else
            s += "-";

        if (flags & PLH::ProtFlag::R)
            s += "r";
        else
            s += "-";

        if (flags & PLH::ProtFlag::W)
            s += "w";
        else
            s += "-";

        if (flags & PLH::ProtFlag::NONE)
            s += "n";
        else
            s += "-";

        if(flags & PLH::ProtFlag::P)
            s += " private";
        else if(flags & PLH::ProtFlag::S)
            s += " shared";
        return s;
    }

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

