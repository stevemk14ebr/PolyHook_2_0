//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#define POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include "../MemoryBlock.hpp"

namespace PLH
{
    class MemAllocatorUnix : public virtual PLH::Errant
    {
    public:
        int TranslateProtection(PLH::ProtFlag flags);

        uint8_t* AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress,
                                        size_t Size, PLH::ProtFlag Protections);

    protected:
        std::vector<PLH::MemoryBlock> GetAllocatedVABlocks();
        std::vector<PLH::MemoryBlock> GetFreeVABlocks();
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

    //[MinAddress, MaxAddress)
    uint8_t* PLH::MemAllocatorUnix::AllocateMemory(uint64_t MinAddress,
                                                   uint64_t MaxAddress,
                                                   size_t Size,
                                                   PLH::ProtFlag Protections)
    {
        int Flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED; //TO-DO make use of MAP_32Bit for x64?
        std::vector<PLH::MemoryBlock> FreeBlocks = GetFreeVABlocks();

        int PageSize = getpagesize();
        for(PLH::MemoryBlock FreeBlock : FreeBlocks)
        {
            //Check acceptable ranges of block size within our Min-Max params
            if(FreeBlock.GetStart() >= MinAddress && FreeBlock.GetEnd() + Size < MaxAddress)
            {
                /*This is the normal case where the entire block is within our range. We now can walk
                 * the memory pages normally until we have a successful allocation*/
                for(uint64_t Cur = FreeBlock.GetAlignedFirstPage(PageSize);
                    Cur != NULL;
                    Cur = FreeBlock.GetAlignedNextPage(Cur,PageSize,PageSize))
                {
                    void* Buffer = mmap((void*)Cur,Size,TranslateProtection(Protections),Flags,0,0);
                    if(Buffer != MAP_FAILED) {
                        return (uint8_t *) Buffer;
                    }
                }
            }else if(FreeBlock.GetEnd() >= MinAddress + Size && FreeBlock.GetStart() < MinAddress){
                /*This is the case where our blocks upper range overlaps the minimum range of our range, but the
                * majority of the lower range of the block is not in our range*/
                std::cout << "Found Edge Min Range Block" << std::endl;
            }else if(FreeBlock.GetStart() + Size < MaxAddress && FreeBlock.GetEnd() > MaxAddress){
                /*This is the case where our blocks lower range overlaps the maximum of our range, but the
                 * majority of the blocks upper range is not in our range*/
                std::cout << "Found Edge Max Range Block" << std::endl;
            }
        }
        std::cout << "No Block Found" << std::endl;
        return nullptr;
    }

    /*Parse linux maps file, these are regions of memory already allocated. If a
     * region is allocated the protection of that region is returned. If it is not
     * allocated then the value UNSET is returned*/
    std::vector<PLH::MemoryBlock> PLH::MemAllocatorUnix::GetAllocatedVABlocks(){
        std::vector<PLH::MemoryBlock> allocatedPages;

        char szMapPath[256] = {0};
        sprintf(szMapPath, "/proc/%ld/maps", getpid( ));
        std::ifstream file(szMapPath);
        std::string line;
        while( getline( file, line ) ) {
            std::stringstream iss(line);
            uint64_t Start;
            uint64_t End;
            char delimiter,r,w,x,p;
            iss >> std::hex >> Start >> delimiter >> End >> r >> w >> x >> p;

            PLH::ProtFlag protFlag = PLH::ProtFlag::UNSET;
            if(x != '-')
                protFlag = protFlag | PLH::ProtFlag::X;

            if(r != '-')
                protFlag = protFlag | PLH::ProtFlag::R;

            if(w != '-')
                protFlag = protFlag | PLH::ProtFlag::W;

            if(p == 'p')
                protFlag = protFlag | PLH::ProtFlag::P;

            if(p == 's')
                protFlag = protFlag | PLH::ProtFlag::S;

            allocatedPages.push_back(PLH::MemoryBlock(Start,End,protFlag));
        }
        return allocatedPages;
    }

    std::vector<PLH::MemoryBlock> PLH::MemAllocatorUnix::GetFreeVABlocks()
    {
        std::vector<PLH::MemoryBlock> FreePages;
        std::vector<PLH::MemoryBlock> AllocatedPages = GetAllocatedVABlocks();
        for(auto prev = AllocatedPages.begin(), cur = AllocatedPages.begin() + 1; cur < AllocatedPages.end(); prev = cur, std::advance(cur,1))
        {
            FreePages.push_back(PLH::MemoryBlock(prev->GetEnd(),cur->GetStart(),PLH::ProtFlag::UNSET));
        }
        return FreePages;
    }
}
#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
