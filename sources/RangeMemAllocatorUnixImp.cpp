//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/UnixImpl/RangeMemAllocatorUnixImp.hpp"

/*******************************************************************************************************
** On Unix virtual address granularity is 4KB. When using MAP_FIXED flag allocation must be page aligned,
** so it is best to call with a size of 4KB to not waste memory.
*******************************************************************************************************/
PLH::Maybe<PLH::AllocatedMemoryBlock>
PLH::RangeMemAllocatorUnixImp::allocateImp(const uint64_t addressOfPage, const size_t size,
                                           const int mapFlags, const PLH::ProtFlag protections) const {

    assert(size > 0 && "Size must be >0");
    auto Buffer = (char*)mmap((char*)addressOfPage, size, TranslateProtection(protections), mapFlags, 0, 0);
    if (Buffer != MAP_FAILED && Buffer != nullptr) {
        //Custom deleter
        std::shared_ptr<char> BufferSp(Buffer, [=](char* ptr) {
            deallocate(ptr, size);
        });

        PLH::MemoryBlock BufferDesc(addressOfPage, addressOfPage + size, protections);
        return PLH::AllocatedMemoryBlock(BufferSp, BufferDesc);
    }
    function_fail("Allocation failed");
}

//[MinAddress, MaxAddress)
PLH::Maybe<PLH::AllocatedMemoryBlock>
PLH::RangeMemAllocatorUnixImp::allocateMemory(const uint64_t minAddress,
                                              const uint64_t maxAddress,
                                              const size_t size,
                                              const PLH::ProtFlag protections) const {

    int Flags = MAP_PRIVATE |
                MAP_ANONYMOUS |
                MAP_FIXED; //TO-DO make use of MAP_32Bit for x64?

    std::vector<PLH::MemoryBlock> FreeBlocks = getFreeVABlocks();

    auto   PageSize  = (size_t)getpagesize();
    size_t Alignment = PageSize;

    for (PLH::MemoryBlock FreeBlock : FreeBlocks) {
        //Check acceptable ranges of block size within our Min-Max params
        if (FreeBlock.getStart() >= minAddress && FreeBlock.getEnd() + size < maxAddress) {
            assert(FreeBlock.getEnd() + size > FreeBlock.getEnd() && "Check for wrap-around");

            /*This is the normal case where the entire block is within our range. We now can walk
             * the memory pages normally until we have a successful allocation*/
            for (auto Cur = FreeBlock.getAlignedFirst(Alignment, PageSize);
                 Cur;
                 Cur = FreeBlock.getAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = allocateImp(Cur.unwrap(), size, Flags, protections))
                    return AllocatedBlock;
            }
        } else if (FreeBlock.getEnd() >= minAddress + size && FreeBlock.getStart() < minAddress) {
            assert(minAddress + size > minAddress && "Check for wrap-around");

            /*This is the case where our blocks upper range overlaps the minimum range of our range, but the
            * majority of the lower range of the block is not in our range*/
            for (auto Cur = FreeBlock.getAlignedNearestUp(minAddress, Alignment, PageSize);
                 Cur && (Cur.unwrap() + size) <= maxAddress;
                 Cur = FreeBlock.getAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = allocateImp(Cur.unwrap(), size, Flags, protections))
                    return AllocatedBlock;
            }
        } else if (FreeBlock.getStart() + size < maxAddress && FreeBlock.getEnd() > maxAddress) {
            assert(FreeBlock.getStart() + size > FreeBlock.getStart() && "Check for wrap-around");

            /*This is the case where our blocks lower range overlaps the maximum of our range, but the
             * majority of the blocks upper range is not in our range*/
            for (auto Cur = FreeBlock.getAlignedNearestDown(FreeBlock.getStart(), Alignment, PageSize);
                 Cur && (Cur.unwrap() + size) < maxAddress && Cur >= minAddress;
                 Cur = FreeBlock.getAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = allocateImp(Cur.unwrap(), size, Flags, protections))
                    return AllocatedBlock;
            }
        }
    }
    function_fail("Failed to find block within range");
}

void PLH::RangeMemAllocatorUnixImp::deallocate(char* buffer, const size_t length) const {
    munmap(buffer, length);
}

size_t PLH::RangeMemAllocatorUnixImp::queryPrefferedAllocSize() const {
    return (size_t)getpagesize();
}

/********************************************************************************
 ** Parse linux maps file, these are regions of memory already allocated. If a  *
 ** region is allocated the protection of that region is returned. If it is not *
 ** allocated then the value UNSET is returned                                  *
 ********************************************************************************/
std::vector<PLH::MemoryBlock> PLH::RangeMemAllocatorUnixImp::getAllocatedVABlocks() const {
    std::vector<PLH::MemoryBlock> allocatedPages;

    char szMapPath[256] = {0};
    sprintf(szMapPath, "/proc/%ld/maps", (long)getpid());
    std::ifstream file(szMapPath);
    std::string   line;
    while (getline(file, line)) {
        std::stringstream iss(line);
        uint64_t          Start;
        uint64_t          End;
        char              delimiter, r, w, x, p;
        iss >> std::hex >> Start >> delimiter >> End >> r >> w >> x >> p;

        PLH::ProtFlag protFlag = PLH::ProtFlag::UNSET;
        if (x != '-')
            protFlag = protFlag | PLH::ProtFlag::X;

        if (r != '-')
            protFlag = protFlag | PLH::ProtFlag::R;

        if (w != '-')
            protFlag = protFlag | PLH::ProtFlag::W;

        if (p == 'p')
            protFlag = protFlag | PLH::ProtFlag::P;

        if (p == 's')
            protFlag = protFlag | PLH::ProtFlag::S;

        allocatedPages.emplace_back(Start, End, protFlag);
    }
    return allocatedPages;
}

std::vector<PLH::MemoryBlock> PLH::RangeMemAllocatorUnixImp::getFreeVABlocks() const {
    std::vector<PLH::MemoryBlock> FreePages;
    std::vector<PLH::MemoryBlock> AllocatedPages = getAllocatedVABlocks();
    for (auto                     prev           = AllocatedPages.begin(), cur = AllocatedPages.begin() + 1;
         cur < AllocatedPages.end(); prev = cur, std::advance(cur, 1)) {
        if (prev->getEnd() - cur->getStart() > 0) {
            FreePages.emplace_back(prev->getEnd(), cur->getStart(), PLH::ProtFlag::UNSET);
        }
    }
    return FreePages;
}
