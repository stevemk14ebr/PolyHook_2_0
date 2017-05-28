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
            const std::size_t AllocationSize = count*sizeof(value_type);
            const std::size_t NeededAlignment = std::alignment_of<value_type>::value;
            std::size_t Allocated = 0;
            uint64_t AllocationStart = 0;
            uint64_t LastAllocEnd = 0; //used to verify children are contiguous
            std::vector<PLH::AllocatedMemoryBlock> AllocatedBlocks;

            /*****************************************************************************************
             **  Splits "parent" memory pages into "child" blocks. If required allocation size spans
             **  multiple "parent" blocks then child blocks are contiguously allocated and a pointer
             **  to the first child is returned. Child blocks are always within one and only one
             **  "parent" block, but they may be chained together so that the returned buffer appears
             **  to be over multiple "parent" blocks.
             **
             **  NOTE: AllocationFailure exception is thrown when allocation of new contiguous "parent"
             **  block fails.
             ******************************************************************************************/
            int Attempts = 0;
            do {
                AllocatedBlocks =  m_AllocImp.GetAllocatedBlocks();
                if (auto NewChild = FindAndSplitBlock(AllocatedBlocks, AllocationSize - Allocated, NeededAlignment))
                {
                    PLH::MemoryBlock NewChildDesc = NewChild.get().GetDescription();
                    if(Allocated == 0) {
                        //Special case for first child
                        AllocationStart = NewChildDesc.GetStart();
                        LastAllocEnd = AllocationStart;
                    }

                    /* failed to allocate contiguous memory (implicitly required by the standard)
                     * https://stackoverflow.com/questions/17878011/are-standard-allocators-required-to-allocate-contiguous-memory*/
                    if(NewChildDesc.GetStart() != LastAllocEnd)
                        throw AllocationFailure();

                    LastAllocEnd = NewChildDesc.GetEnd();
                    Allocated += NewChildDesc.GetSize();
                } else {
                    //Allocate a new memory page "parent" block and add it to the map, give it no children yet
                    auto NewParent = m_AllocImp.AllocateMemory(m_AllowedRegion.GetStart(), m_AllowedRegion.GetEnd(),
                                                               m_AllocImp.QueryPreferedAllocSize(),
                                                               PLH::ProtFlag::R | PLH::ProtFlag::W);
                    if(NewParent) {
                        m_SplitBlockMap.insert(std::make_pair(NewParent.get(),
                                                              std::vector<PLH::AllocatedMemoryBlock>()));
                    }else{
                        //failed to allocate new page
                        throw AllocationFailure();
                    }
                }
            }while(Allocated < AllocationSize);
            return (pointer)AllocationStart;
        }

        /*********************************************************************************************************************
         ** Attempts to allocate a single child block inside of any parent block. Will allocate either at the start of      **
         ** a new parent block, or at the end of an existing one, gaps are not filled. Will greedily allocate children      **
         ** into the first free space at the end of any parent, even if the space is < DesiredSpace. Therefore, to use      **
         ** properly the size of the returned child must be checked, and this called in loop to allocate up to DesiredSpace **
         *********************************************************************************************************************/
        boost::optional<PLH::AllocatedMemoryBlock&> FindAndSplitBlock(std::vector<PLH::AllocatedMemoryBlock> &AllocatedBlocks,
                                                     std::size_t DesiredSpace, std::size_t RequiredAlignment)
        {
            boost::optional<PLH::AllocatedMemoryBlock&> gaurd;
            for(int i = 0; i < AllocatedBlocks.size(); i++)
            {
                PLH::AllocatedMemoryBlock ParentBlock = AllocatedBlocks[i];
                PLH::MemoryBlock ParentDesc = ParentBlock.GetDescription();

                auto ParentChildPair = m_SplitBlockMap.find(ParentBlock);
                if(ParentChildPair == m_SplitBlockMap.end())
                    continue;
                std::vector<PLH::AllocatedMemoryBlock>& Children = ParentChildPair->second;

                uint64_t ChildBlockStart = 0;
                if(Children.size() == 0)
                {
                    //TO-DO: align this start address, guarantees all following children are aligned
                    //Add first child
                    ChildBlockStart = ParentDesc.GetStart();
                }else if(Children.size() != 0){
                    //Add successive children to end
                    ChildBlockStart = Children.back().GetDescription().GetEnd();
                }else{
                    continue;
                }

                /*
                 * By aligning the start, we ensure that all following allocations are also aligned. This is true because
                 * C/C++ guarantees object size is multiple of alignment:
                 * https://stackoverflow.com/questions/4637774/is-the-size-of-a-struct-required-to-be-an-exact-multiple-of-the-alignment-of-tha
                 * Range checks for possibly rounding up occur in ChildBlockEnd calculations.*/
                ChildBlockStart = (uint64_t)PLH::AlignUpwards((uint8_t*)ChildBlockStart,RequiredAlignment);
                assert(ChildBlockStart % RequiredAlignment == 0);

                uint64_t ChildBlockEnd = 0;
                if(ChildBlockStart + DesiredSpace <= ParentDesc.GetEnd())
                {
                    ChildBlockEnd = ChildBlockStart + DesiredSpace;
                }else if(ParentDesc.GetEnd() - ChildBlockStart > 0){
                    ChildBlockEnd = ParentDesc.GetEnd();
                }else{
                    continue;
                }

                PLH::MemoryBlock NewChildDesc(ChildBlockStart,ChildBlockEnd,ParentDesc.GetProtection());
                PLH::AllocatedMemoryBlock NewChildBlock(ParentBlock.GetParentBlock(), NewChildDesc);

                Children.push_back(NewChildBlock);
                gaurd = Children.back();
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
