//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#define POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#include "../MemAllocator.hpp"
#include <sys/mman.h>

template<>
uint8_t* MemAllocator<PLH::Platform::Unix>::AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress, size_t Size, ProtFlag Protections)
{
    //Tell kernel about where we want our mem, it should handle rounding for us *sanity check later*
    uint64_t HintAddr = MaxAddress - MinAddress;
    int Flags = MAP_PRIVATE | MAP_ANONYMOUS; //TO-DO make use of MAP_32Bit for x64?
    uint8_t* Cave = (uint8_t*)mmap((void*)HintAddr,Size, Protections, Flags, -1, 0);
    m_Caves.emplace_back(Cave);
    
    //TO-DO verify above works, sanity check range, eventually stop wasting whole pages at a time (implement whole mem-manager?)
}


#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
