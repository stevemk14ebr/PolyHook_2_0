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

namespace PLH
{
    class MemAllocatorUnix : public virtual PLH::Errant
    {
    public:
        int TranslateProtection(PLH::ProtFlag flags);

        uint8_t* AllocateMemory(uint64_t MinAddress, uint64_t MaxAddress,
                                        size_t Size, PLH::ProtFlag Protections);
    private:
        PLH::ProtFlag GetPageProtection(uint64_t Address);
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
        int Flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED; //TO-DO make use of MAP_32Bit for x64?
        return nullptr;
    }

    /*Parse linux maps file, these are regions of memory already allocated. If a
     * region is allocated the protection of that region is returned. If it is not
     * allocated then the value UNSET is returned*/
    PLH::ProtFlag MemAllocatorUnix::GetPageProtection(uint64_t Address)
    {
        char szMapPath[256] = {0};
        sprintf(szMapPath, "/proc/%ld/maps", getpid( ));
        std::ifstream file(szMapPath);
        std::string line;
        while( getline( file, line ) ) {
            std::cout << line << std::endl;
            std::stringstream iss(line);
            uint64_t Start;
            uint64_t End;
            char delimeter,r,w,x,p;
            iss >> std::hex >> Start >> delimeter >> End >> r >> w >> x >> p;

            //valid range is [Start,End]
            if(Start > Address || End < Address)
                continue;

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
            return protFlag;
        }
        return PLH::ProtFlag::UNSET;
    }
}
#endif //POLYHOOK_2_0_MEMALLOCATORUNIX_HPP
