//
// Created by steve on 4/25/17.
//

#ifndef POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#define POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#include <memory>
#include <map>
#include <type_traits>
#include <algorithm>
#include "ARangeMemAllocator.hpp"

//General Allocator Design: https://www.youtube.com/watch?v=LIb3L4vKZ7U
//Design Inspiration: http://jrruethe.github.io/blog/2015/11/22/allocators/
namespace PLH
{
    template<typename T>
    struct max_allocations
    {
        enum{value = static_cast<std::size_t>(-1) / sizeof(T)};
    };

    /******************************************************************************************************
    **  This class handles actually splitting AllocatedMemoryBlocks into smaller AllocatedMemoryBlocks and
    **  then serving the smaller chunks up to whatever uses the allocator. It deals with the mapping of
    **  larger "Parent" blocks to all of the parent's "Children" blocks via a map.
    ******************************************************************************************************/
    template<class T,class Platform>
    class RangeMemoryAllocatorPolicy
    {
    public:
        typedef T value_type;
        typedef value_type* pointer;
        typedef const value_type* const_pointer;
        typedef value_type& reference;
        typedef const value_type& const_reference;
        typedef std::size_t size_type;
        typedef std::ptrdiff_t difference_type;

        RangeMemoryAllocatorPolicy(uint64_t Min, uint64_t Max)
        {
            m_AllowedRegion = PLH::MemoryBlock(Min,Max,PLH::UNSET);
        }

        pointer allocate(size_type count, const_pointer = 0)
        {
            std::size_t AllocationSize = count*sizeof(value_type);
            std::size_t NeededAlignment = std::alignment_of<value_type>::value;
            std::vector<PLH::AllocatedMemoryBlock> AllocatedBlocks;

            int Attempts = 0;
            do {
                //First try to find a big enough parent block to split
                AllocatedBlocks =  m_AllocImp.GetAllocatedBlocks();
                if (PLH::AllocatedMemoryBlock* NewChild = FindAndSplitBlock(AllocatedBlocks, AllocationSize)) {
                    return (pointer)NewChild->GetDescription().GetStart();
                } else {
                    //Allocate a new memory page "parent" block and add it to the map, give it no children yet
                    m_SplitBlockMap.insert(std::make_pair(
                            m_AllocImp.AllocateMemory(m_AllowedRegion.GetStart(), m_AllowedRegion.GetEnd(), getpagesize(),
                                              PLH::ProtFlag::R | PLH::ProtFlag::W),
                            std::vector<PLH::AllocatedMemoryBlock>()));
                }
            }while(++Attempts < 2);
            return nullptr;
        }

        PLH::AllocatedMemoryBlock* FindAndSplitBlock(std::vector<PLH::AllocatedMemoryBlock> &AllocatedBlocks,
                                                     std::size_t RequiredSpace)
        {
            for(int i = 0; i < AllocatedBlocks.size(); i++)
            {
                PLH::AllocatedMemoryBlock* Block = &AllocatedBlocks[i];
                assert(Block != nullptr);

                uint64_t BlockSize = Block->GetSize();
                uint64_t BlockUsed = 0;
                auto it = m_SplitBlockMap.find(*Block);
                if(it == m_SplitBlockMap.end())
                    continue;

                //Calculate how much space children of parent already use
                std::vector<PLH::AllocatedMemoryBlock> Children = it->second;
                for(const auto& ChildBlock : Children)
                {
                    BlockUsed += ChildBlock.GetSize();
                }

                //if there is no room left in the parent block for us
                if(BlockUsed + RequiredSpace > BlockSize)
                    continue;

                PLH::MemoryBlock NewChildDesc((uint64_t)(Block->GetParentBlock().get() + BlockUsed),
                                              (uint64_t )(Block->GetParentBlock().get() + BlockUsed + RequiredSpace),
                                                Block->GetDescription().GetProtection());
                PLH::AllocatedMemoryBlock NewChildBlock(Block->GetDescription(), Block->GetParentBlock(),NewChildDesc);
                it->second.push_back(NewChildBlock);
                return &it->second.back();
            }
            return nullptr;
        }

        void deallocate(pointer ptr, size_type n)
        {
            PLH::MemoryBlock block((uint64_t)ptr,(uint64_t)ptr + n,PLH::ProtFlag::UNSET);
            for(auto& ParentKeyValuePair : m_SplitBlockMap)
            {
                if(ParentKeyValuePair.first.ContainsBlock(block))
                {
                    ParentKeyValuePair.second.erase(
                            std::remove(ParentKeyValuePair.second.begin(),
                                        ParentKeyValuePair.second.end(), block),
                            ParentKeyValuePair.second.end());
                }
            }
        }

        template<typename U>
        struct rebind
        {
            typedef RangeMemoryAllocatorPolicy<U,Platform> other;
        };

        bool operator==(PLH::RangeMemoryAllocatorPolicy<T, Platform> const& other)
        {
            return m_AllowedRegion == other.m_AllowedRegion;
        }

        bool operator!=(PLH::RangeMemoryAllocatorPolicy<T,Platform> const& other)
        {
            return !(other == *this);
        }
        size_type max_size(void) const {return max_allocations<T>::value;}
    private:
        PLH::ARangeMemAllocator<Platform> m_AllocImp;
        PLH::MemoryBlock m_AllowedRegion;
        std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>> m_SplitBlockMap;
    };

    template<typename T,typename Platform, typename OtherAllocator>
    inline bool operator==(PLH::RangeMemoryAllocatorPolicy<T, Platform> const&,
                           OtherAllocator const&) {
        return false;
    }

    bool operator==(const PLH::AllocatedMemoryBlock& allocated, const PLH::MemoryBlock& block)
    {
        return false;
    }
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
