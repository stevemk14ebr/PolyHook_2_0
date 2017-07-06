//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/UnixImpl/RangeMemAllocatorUnixImp.hpp"

int PLH::RangeMemAllocatorUnixImp::TranslateProtection(const PLH::ProtFlag flags) const {
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

/*******************************************************************************************************
** On Unix virtual address granularity is 4KB. When using MAP_FIXED flag allocation must be page aligned,
** so it is best to call with a size of 4KB to not waste memory.
*******************************************************************************************************/
PLH::Maybe<PLH::AllocatedMemoryBlock>
PLH::RangeMemAllocatorUnixImp::AllocateImp(const uint64_t AddressOfPage, const size_t Size,
                                           const int MapFlags, const PLH::ProtFlag Protections) const {

    assert(Size > 0 && "Size must be >0");
    uint8_t* Buffer = (uint8_t*)mmap((void*)AddressOfPage, Size, TranslateProtection(Protections), MapFlags, 0, 0);
    if (Buffer != MAP_FAILED && Buffer != nullptr) {
        //Custom deleter
        std::shared_ptr<uint8_t> BufferSp(Buffer, [=](uint8_t* ptr) {
            Deallocate(ptr, Size);
        });

        PLH::MemoryBlock BufferDesc(AddressOfPage, AddressOfPage + Size, Protections);
        return PLH::AllocatedMemoryBlock(BufferSp, BufferDesc);
    }
    function_fail("Allocation failed");
}

//[MinAddress, MaxAddress)
PLH::Maybe<PLH::AllocatedMemoryBlock>
PLH::RangeMemAllocatorUnixImp::AllocateMemory(const uint64_t MinAddress,
                                              const uint64_t MaxAddress,
                                              const size_t Size,
                                              const PLH::ProtFlag Protections) const {

    int Flags = MAP_PRIVATE |
                MAP_ANONYMOUS |
                MAP_FIXED; //TO-DO make use of MAP_32Bit for x64?
    std::vector<PLH::MemoryBlock> FreeBlocks = GetFreeVABlocks();

    size_t PageSize = (size_t)getpagesize();
    size_t Alignment = PageSize;
    for (PLH::MemoryBlock FreeBlock : FreeBlocks) {
        //Check acceptable ranges of block size within our Min-Max params
        if (FreeBlock.GetStart() >= MinAddress && FreeBlock.GetEnd() + Size < MaxAddress) {
            assert(FreeBlock.GetEnd() + Size > FreeBlock.GetEnd() && "Check for wrap-around");
            /*This is the normal case where the entire block is within our range. We now can walk
             * the memory pages normally until we have a successful allocation*/
            for (auto Cur = FreeBlock.GetAlignedFirst(Alignment, PageSize);
                 Cur;
                 Cur = FreeBlock.GetAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = AllocateImp(Cur.unwrap(), Size, Flags, Protections))
                    return AllocatedBlock;
            }
        } else if (FreeBlock.GetEnd() >= MinAddress + Size && FreeBlock.GetStart() < MinAddress) {
            assert(MinAddress + Size > MinAddress && "Check for wrap-around");
            /*This is the case where our blocks upper range overlaps the minimum range of our range, but the
            * majority of the lower range of the block is not in our range*/
            for (auto Cur = FreeBlock.GetAlignedNearestUp(MinAddress, Alignment, PageSize);
                 Cur && (Cur.unwrap() + Size) <= MaxAddress;
                 Cur = FreeBlock.GetAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = AllocateImp(Cur.unwrap(), Size, Flags, Protections))
                    return AllocatedBlock;
            }
        } else if (FreeBlock.GetStart() + Size < MaxAddress && FreeBlock.GetEnd() > MaxAddress) {
            assert(FreeBlock.GetStart() + Size > FreeBlock.GetStart() && "Check for wrap-around");
            /*This is the case where our blocks lower range overlaps the maximum of our range, but the
             * majority of the blocks upper range is not in our range*/
            for (auto Cur = FreeBlock.GetAlignedNearestDown(FreeBlock.GetStart(), Alignment, PageSize);
                 Cur && (Cur.unwrap() + Size) < MaxAddress && Cur >= MinAddress;
                 Cur = FreeBlock.GetAlignedNext(Cur.unwrap(), Alignment, PageSize)) {
                if (auto AllocatedBlock = AllocateImp(Cur.unwrap(), Size, Flags, Protections))
                    return AllocatedBlock;
            }
        }
    }
    function_fail("Failed to find block within range");
}

void PLH::RangeMemAllocatorUnixImp::Deallocate(uint8_t* Buffer, const size_t Length) const {
    munmap(Buffer, Length);
}

size_t PLH::RangeMemAllocatorUnixImp::QueryPreferedAllocSize() const {
    return (size_t)getpagesize();
}

/********************************************************************************
 ** Parse linux maps file, these are regions of memory already allocated. If a  *
 ** region is allocated the protection of that region is returned. If it is not *
 ** allocated then the value UNSET is returned                                  *
 ********************************************************************************/
std::vector<PLH::MemoryBlock> PLH::RangeMemAllocatorUnixImp::GetAllocatedVABlocks() const {
    std::vector<PLH::MemoryBlock> allocatedPages;

    char szMapPath[256] = {0};
    sprintf(szMapPath, "/proc/%ld/maps", (long)getpid());
    std::ifstream file(szMapPath);
    std::string line;
    while (getline(file, line)) {
        std::stringstream iss(line);
        uint64_t Start;
        uint64_t End;
        char delimiter, r, w, x, p;
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

        allocatedPages.push_back(PLH::MemoryBlock(Start, End, protFlag));
    }
    return allocatedPages;
}

std::vector<PLH::MemoryBlock> PLH::RangeMemAllocatorUnixImp::GetFreeVABlocks() const {
    std::vector<PLH::MemoryBlock> FreePages;
    std::vector<PLH::MemoryBlock> AllocatedPages = GetAllocatedVABlocks();
    for (auto prev = AllocatedPages.begin(), cur = AllocatedPages.begin() + 1;
         cur < AllocatedPages.end(); prev = cur, std::advance(cur, 1)) {
        if (prev->GetEnd() - cur->GetStart() > 0) {
            FreePages.push_back(PLH::MemoryBlock(prev->GetEnd(), cur->GetStart(), PLH::ProtFlag::UNSET));
        }
    }
    return FreePages;
}
