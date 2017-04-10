//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#define POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#include <sys/mman.h>

namespace PLH
{
    class MemAllocatorUnix : public virtual PLH::Errant
    {
    public:
        int TranslateProtection(PLH::ProtFlag flags);

        uint8_t* AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress,
                                        size_t Size, PLH::ProtFlag Protections);
    };

    int PLH::MemAllocatorUnix::TranslateProtection(PLH::ProtFlag flags)
    {

        int NativeFlag = 0;
        if (flags & PLH::ProtFlag::X)
            NativeFlag |= PROT_EXEC;

        if (flags & PLH::ProtFlag::R)
            NativeFlag |= PROT_READ;

        if (flags & PLH::ProtFlag::W)
            NativeFlag |= PROT_WRITE;

        if (flags & PLH::ProtFlag::NONE)
            NativeFlag |= PROT_NONE;
        return NativeFlag;
    }

    uint8_t* PLH::MemAllocatorUnix::AllocateMemory(uint64_t MinAddress,
                                                   uint64_t MaxAddress,
                                                   size_t Size,
                                                   PLH::ProtFlag Protections)
    {
        //Tell kernel about where we want our mem, it should handle rounding for us *sanity check later*
        uint64_t HintAddr = MaxAddress - MinAddress;
        int Flags = MAP_PRIVATE | MAP_ANONYMOUS; //TO-DO make use of MAP_32Bit for x64?
        uint8_t *Cave = (uint8_t *)mmap((void *) HintAddr, Size, this->TranslateProtection(Protections), Flags, -1, 0);
        return Cave;
    }
}
#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
