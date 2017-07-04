//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X64DETOURIMPL_HPP
#define POLYHOOK_2_X64DETOURIMPL_HPP

#include "src/Maybe.hpp"
#include "src/MemoryAllocation/RangeAllocator.hpp"

#include <vector>
#include <src/IHook.hpp>

class x64DetourImpl
{
public:
    //TODO: Make the allocator typedef a template argument to class
    typedef PLH::RangeAllocator<int, PLH::MemAllocatorUnix> LinuxAllocator;
    typedef std::vector<uint8_t,  LinuxAllocator> DetourBuffer;

    PLH::Maybe<DetourBuffer> AllocateMemory(const uint64_t Hint);

    PLH::HookType GetType() const;
};


PLH::Maybe<DetourBuffer> x64DetourImpl::AllocateMemory(const uint64_t Hint) {
    uint64_t MinAddress = Hint < 0x80000000 ? 0 : Hint - 0x80000000;            //Use 0 if would underflow
    uint64_t MaxAddress = Hint > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                          std::numeric_limits<uint64_t>::max() : Hint + 0x80000000;

    DetourBuffer alloc_vec(LinuxAllocator(MinAddress, MaxAddress));
    return alloc_vec;
}

PLH::HookType x64DetourImpl::GetType() const {
    return PLH::HookType::X64Detour;
}

#endif //POLYHOOK_2_X64DETOURIMPL_HPP
