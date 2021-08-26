#ifndef POLYHOOK_2_PAGEALLOCATOR_HPP
#define POLYHOOK_2_PAGEALLOCATOR_HPP

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/FBAllocator.hpp"

namespace PLH { 

// wrapper over fb_allocator in C, with heap backing from VirtualAlloc2 to enforce range
class FBAllocator
{
public:
    FBAllocator(uint64_t min, uint64_t max, uint8_t blockSize, uint8_t blockCount);
    ~FBAllocator();
    bool initialize();

    char* allocate();

    char* callocate(uint8_t num);

    void deallocate(char* mem);

    bool inRange(uint64_t addr);

    bool intersectsRange(uint64_t min, uint64_t max);

    // if a range intersections, by what % of the given range is the overlap
    uint8_t intersectionLoadFactor(uint64_t min, uint64_t max);
private:
    bool m_alloc2Supported;
    uint8_t m_usedBlocks;
    uint8_t m_maxBlocks;
    uint8_t m_blockSize;
    uint64_t m_min;
    uint64_t m_max;
    uint64_t m_dataPool;

    ALLOC_Allocator* m_allocator;
    ALLOC_HANDLE m_hAllocator;
};

class RangeAllocator
{
public:
    RangeAllocator(uint8_t blockSize, uint8_t blockCount);
    ~RangeAllocator() = default;

    char* allocate(uint64_t min, uint64_t max);
    void deallocate(uint64_t addr);
private:
    std::shared_ptr<FBAllocator> findOrInsertAllocator(uint64_t min, uint64_t max);

    uint8_t m_maxBlocks;
    uint8_t m_blockSize;
    std::mutex m_mutex;
    std::vector<std::shared_ptr<FBAllocator>> m_allocators;
    std::unordered_map<uint64_t, std::shared_ptr<FBAllocator>> m_allocMap;
};

}

#endif