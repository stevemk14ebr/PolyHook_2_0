//
// Created by steve on 4/25/17.
//

#ifndef POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#define POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#include <memory>
#include <map>
#include <type_traits>
#include "ARangeMemAllocator.hpp"

#define ALLOCATOR_TRAITS(T)                \
typedef T                 type;            \
typedef type              value_type;      \
typedef value_type*       pointer;         \
typedef value_type const* const_pointer;   \
typedef value_type&       reference;       \
typedef value_type const& const_reference; \
typedef std::size_t       size_type;       \
typedef std::ptrdiff_t    difference_type; \

//http://jrruethe.github.io/blog/2015/11/22/allocators/
namespace PLH
{
    /* ****************************************************************************************************
    *  This class handles actually splitting AllocatedMemoryBlocks into smaller AllocatedMemoryBlocks. It
    *  deals with the mapping of larger "Parent" blocks to all of the parent's "Children" blocks via a map.
    ******************************************************************************************************/
    template<class T>
    class RangeMemoryAllocatorPolicy
    {
    public:
        ALLOCATOR_TRAITS(T)

        RangeMemoryAllocatorPolicy(PLH::ARangeMemAllocator& AllocImp) : std::allocator_traits<T>()
        {
            m_AllocImp = AllocImp;
        }

        pointer allocate(size_type count, const_pointer = 0)
        {
            std::size_t AllocationSize = count*sizeof(value_type);
            std::size_t NeededAlignment = std::alignment_of<value_type>::value;
            std::vector<PLH::AllocatedMemoryBlock> AllocatedBlocks = m_AllocImp.GetAllocatedCaves();
            if(auto ParentBlock = FindSplittableBlock(AllocatedBlocks,AllocationSize))
            {
                //TO-DO: Split the block
            }else{
                //TO-DO: Fail appropriately
            }
        }

        PLH::Optional<PLH::AllocatedMemoryBlock> FindSplittableBlock(const std::vector<PLH::AllocatedMemoryBlock>& AllocatedBlocks,
                                                      std::size_t RequiredSpace)
        {
            for(const auto& Block : AllocatedBlocks)
            {
                uint64_t BlockSize = Block.GetSize();
                uint64_t BlockUsed = 0;
                auto it = m_SplitBlockMap.find(Block);
                if(it == m_SplitBlockMap.end())
                    continue;

                std::vector<PLH::AllocatedMemoryBlock> Children = it->second;
                for(const auto& ChildBlock : Children)
                {
                    BlockUsed += ChildBlock.GetSize();
                }

                if(BlockUsed + RequiredSpace < BlockSize)
                    return PLH::Optional<PLH::AllocatedMemoryBlock>(Block);
            }
            return PLH::Optional<PLH::AllocatedMemoryBlock>();
        }

        void deallocate(pointer ptr, size_type n)
        {

        }

        ~RangeMemoryAllocatorPolicy()
        {

        }
    private:
        PLH::ARangeMemAllocator m_AllocImp;
        std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>> m_SplitBlockMap;
    };
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
