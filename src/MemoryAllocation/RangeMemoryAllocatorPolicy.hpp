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

            /* Loop avoids overhead/complication of recursion
             * First attempt: possible no blocks are allocated yet, or cur block is full
             * Second attempt: allocate a new block
             * Third attempt: if condition should now succeed*/
            int Attempts = 0;
            do {
                //First try to find a big enough parent block to split
                AllocatedBlocks =  m_AllocImp.GetAllocatedBlocks();
                if (auto NewChild = FindAndSplitBlock(AllocatedBlocks, AllocationSize)) {
                    return (pointer)NewChild.get()->GetDescription().GetStart();
                } else {
                    //Allocate a new memory page "parent" block and add it to the map, give it no children yet
                    auto NewParent = m_AllocImp.AllocateMemory(m_AllowedRegion.GetStart(), m_AllowedRegion.GetEnd(),
                                                               getpagesize(),
                                                               PLH::ProtFlag::R | PLH::ProtFlag::W);
                    if(NewParent) {
                        std::cout << NewParent.get() << std::endl;
                        m_SplitBlockMap.insert(std::make_pair(NewParent.get(),
                                std::vector<PLH::AllocatedMemoryBlock>()));
                    }
                }
            }while(Attempts++ < 2);

            //TO-DO: this can be avoided by properly splitting RequiredSize across multiple allocations.
            //When we do this we need to verify that the allocated chunks are contiguous
            throw AllocationFailure();
            return nullptr;
        }

        //TO-DO: fix alignment
        boost::optional<PLH::AllocatedMemoryBlock*> FindAndSplitBlock(std::vector<PLH::AllocatedMemoryBlock> &AllocatedBlocks,
                                                     std::size_t RequiredSpace)
        {
            boost::optional<PLH::AllocatedMemoryBlock*> gaurd;
            for(int i = 0; i < AllocatedBlocks.size(); i++)
            {
                PLH::AllocatedMemoryBlock* ParentBlock = &AllocatedBlocks[i];
                assert(ParentBlock != nullptr);
                PLH::MemoryBlock ParentDesc = ParentBlock->GetDescription();

                auto ParentChildPair = m_SplitBlockMap.find(*ParentBlock);
                if(ParentChildPair == m_SplitBlockMap.end())
                    continue;
                std::vector<PLH::AllocatedMemoryBlock>& Children = ParentChildPair->second;

                PLH::MemoryBlock NewChildDesc;
                if(Children.size() == 0 && RequiredSpace <= ParentBlock->GetSize())
                {
                    //Add first child
                    NewChildDesc = PLH::MemoryBlock(ParentDesc.GetStart(), ParentDesc.GetStart() + RequiredSpace,
                                                    ParentDesc.GetProtection());
                }else if(Children.size() != 0){
                    //Check if there's room for a new child at the end
                    PLH::MemoryBlock LastChildDesc = Children.back().GetDescription();
                    uint64_t NewChildEnd = LastChildDesc.GetEnd() + RequiredSpace;
                    if(!ParentDesc.ContainsAddress(NewChildEnd))
                        continue;

                    NewChildDesc = PLH::MemoryBlock(Children.back().GetDescription().GetEnd(), NewChildEnd,
                                                  ParentDesc.GetProtection());
                }else{
                    continue;
                }
                PLH::AllocatedMemoryBlock NewChildBlock(ParentBlock->GetParentBlock(), NewChildDesc);

                Children.push_back(NewChildBlock);
                gaurd = &Children.back();
                return gaurd;
            }
            return gaurd;
        }

        void deallocate(pointer ptr, size_type n)
        {
            for(auto& ParentKeyValuePair : m_SplitBlockMap)
            {
                //TO-DO fix this
                PLH::MemoryBlock block((uint64_t)ptr,(uint64_t)ptr + n*sizeof(T), ParentKeyValuePair.first.GetDescription().GetProtection());
                PLH::AllocatedMemoryBlock allocblock(ParentKeyValuePair.first.GetParentBlock(), block);
                if(ParentKeyValuePair.first.ContainsBlock(allocblock))
                {
                    ParentKeyValuePair.second.erase(
                            std::remove(ParentKeyValuePair.second.begin(),
                                        ParentKeyValuePair.second.end(), allocblock),
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

        size_type max_size(void) const
        {
            return std::numeric_limits<size_type>::max() / sizeof(value_type);
        }
    private:
        //[Start,End)
        bool IsInRange(uint64_t Address)
        {
            return Address >= m_AllowedRegion.GetStart() && Address < m_AllowedRegion.GetEnd();
        }
        PLH::ARangeMemAllocator<Platform> m_AllocImp;
        PLH::MemoryBlock m_AllowedRegion;
        std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>> m_SplitBlockMap;
    };

    template<typename T,typename Platform, typename OtherAllocator>
    inline bool operator==(PLH::RangeMemoryAllocatorPolicy<T, Platform> const&,
                           OtherAllocator const&) {
        return false;
    }
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
