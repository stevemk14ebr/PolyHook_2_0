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
                        m_SplitBlockMap.insert(std::make_pair(NewParent.get(),
                                std::vector<PLH::AllocatedMemoryBlock>()));
                    }
                }
            }while(Attempts++ < 3);
            return nullptr;
        }

        boost::optional<PLH::AllocatedMemoryBlock*> FindAndSplitBlock(std::vector<PLH::AllocatedMemoryBlock> &AllocatedBlocks,
                                                     std::size_t RequiredSpace)
        {
            boost::optional<PLH::AllocatedMemoryBlock*> AllocatedBlock;
            for(int i = 0; i < AllocatedBlocks.size(); i++)
            {
                PLH::AllocatedMemoryBlock* CurBlock = &AllocatedBlocks[i];
                assert(CurBlock != nullptr);

                //Find the children associated with parent block
                uint64_t BlockSize = CurBlock->GetSize();
                auto it = m_SplitBlockMap.find(*CurBlock);
                if(it == m_SplitBlockMap.end())
                    continue;

                //Search for existing gaps in children we can use
                std::vector<PLH::AllocatedMemoryBlock> Children = it->second;
                boost::optional<PLH::MemoryBlock> NewChildDesc;
                for(auto prev = Children.begin(), cur = Children.begin() + 1; cur < Children.end(); prev = cur, std::advance(cur,1))
                {
                    //gap too small
                    if(prev->GetDescription().GetEnd() - cur->GetDescription().GetStart() < RequiredSpace)
                        continue;

                    //make sure region is aligned for T
                    PLH::MemoryBlock CandidateRegion(prev->GetDescription().GetEnd(), cur->GetDescription().GetStart(), CurBlock->GetDescription().GetProtection());
                    if(CandidateRegion.GetStart() % std::alignment_of<T>::value == 0) {
                        //Is properly aligned and region is big enough
                        NewChildDesc == CandidateRegion;
                        break;
                    }else{
                        //region wasn't aligned, so do so, now we have to check it's still big enough
                        uint64_t AlignedCandidateStart = CandidateRegion.GetStart() + (CandidateRegion.GetStart() % std::alignment_of<T>::value);
                        if(CandidateRegion.GetEnd() - AlignedCandidateStart < RequiredSpace)
                            continue;

                        //region now aligned and is big enough
                        NewChildDesc = PLH::MemoryBlock(AlignedCandidateStart, CandidateRegion.GetEnd(), CurBlock->GetDescription().GetProtection());
                        break;
                    }
                }

                //no usable gap found in children, add one at end
                if(!NewChildDesc)
                {
                    uint64_t Start;
                    if(Children.size() > 0)
                        Start = Children.back().GetDescription().GetEnd();
                    else
                        Start = CurBlock->GetDescription().GetStart();

                    Start += Start % std::alignment_of<T>::value;
                    uint64_t End = Start + RequiredSpace;
                    if(End - Start < RequiredSpace)
                        continue;

                    NewChildDesc = PLH::MemoryBlock(Start,End,CurBlock->GetDescription().GetProtection());
                }
                //double check all the math above
                if(!IsInRange(NewChildDesc.get().GetStart()) || !IsInRange(NewChildDesc.get().GetEnd()))
                    continue;

                PLH::AllocatedMemoryBlock NewChildBlock(CurBlock->GetDescription(), CurBlock->GetParentBlock(),NewChildDesc.get());

                it->second.push_back(NewChildBlock);
                AllocatedBlock = &it->second.back();
                return AllocatedBlock;
            }
            return AllocatedBlock;
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

    bool operator==(const PLH::AllocatedMemoryBlock& allocated, const PLH::MemoryBlock& block)
    {
        return false;
    }
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
