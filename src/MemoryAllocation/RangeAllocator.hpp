//
// Created by steve on 4/25/17.
//

#ifndef POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#define POLYHOOK_2_0_MEMORYALLOCATOR_HPP

#include <memory>
#include <map>
#include <type_traits>
#include <algorithm>
#include "src/MemoryAllocation/ARangAllocator.hpp"

//General Allocator Design: https://www.youtube.com/watch?v=LIb3L4vKZ7U
//Design Inspiration: http://jrruethe.github.io/blog/2015/11/22/allocators/
namespace PLH {
/******************************************************************************************************
**  This class handles actually splitting AllocatedMemoryBlocks into smaller AllocatedMemoryBlocks and
**  then serving the smaller chunks up to whatever uses the allocator. It deals with the mapping of
**  larger "Parent" blocks to all of the parent's "Children" blocks via a map. This follows the
**  first fit allocation algorithm with address ordering. This means it allocates at the lower addresses
**  first towards the higher addresses.
******************************************************************************************************/
template<class T, class Platform>
class RangeAllocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    typedef std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>>
            ChildSiblingMap;

    typedef std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>>
            ParentChildMap;

    RangeAllocator(uint64_t Min, uint64_t Max) {
        m_AllowedRegion = PLH::MemoryBlock(Min, Max, PLH::UNSET);
    }

    pointer allocate(size_type count, const_pointer = 0) {
        const std::size_t AllocationSize = count * sizeof(value_type);
        const std::size_t NeededAlignment = std::alignment_of<value_type>::value;
        std::size_t Allocated = 0;
        ChildSiblingMap::iterator ChildChainIt;
        std::vector<PLH::AllocatedMemoryBlock> AllocatedBlocks;

        /****************************************************************************************
         * Sometimes a chain can be in the process of being built, we'll have a few
         * child blocks allocated, and then the gap that we are filling runs out of
         * room. When this happens we call it a "failed chain" and store it to be
         * removed freed later. After we store the failed chain we try to start a new chain.
         * This continues until either then chain is successfully build or
         * parent blocks fail to be allocated. Before this function returns all failed chains
         * are freed.
         *
         * TODO: needs implemented
         * *************************************************************************************/
        std::vector<ChildSiblingMap::iterator> FailedChains;

        /*****************************************************************************************
         **  Splits "parent" memory pages into "child" blocks. If required allocation size spans
         **  multiple "parent" blocks then child blocks are contiguously allocated and a pointer
         **  to the first child is returned. Child blocks are always within one and only one
         **  "parent" block, but they may be chained together so that the returned buffer appears
         **  to be over multiple "parent" blocks. When this chaining occurs the name "sibling" is
         **  used to refer to children blocks (after the first) that have been "grouped" for the same
         **  logical allocation.
         **
         **  NOTE: AllocationFailure exception is thrown when allocation of new contiguous "parent"
         **  block fails.
         ******************************************************************************************/
        int Attempts = 0;
        do {
            AllocatedBlocks = m_AllocImp.GetAllocatedBlocks();
            if (auto NewChild = CreateChildInParent(AllocatedBlocks, AllocationSize - Allocated, NeededAlignment)) {
                PLH::MemoryBlock NewChildDesc = NewChild.get().GetDescription();
                std::cout << *NewChild << std::endl;
                if (Allocated == 0) {
                    //Special case to add first child
                    ChildChainIt = m_ChildSiblingMap.insert({NewChild.get(),
                                              std::vector<PLH::AllocatedMemoryBlock>()}).first;
                } else {
                    //Contiguous allocation check
                    if (ChildChainIt->second.size() == 0) {
                        if (ChildChainIt->first.GetDescription().GetEnd() != NewChildDesc.GetStart())
                            throw AllocationFailure();
                    } else {
                        if (ChildChainIt->second.back().GetDescription().GetEnd() != NewChildDesc.GetStart()) {
                            throw AllocationFailure();
                        }
                    }
                    //Allocations past first must be siblings, add them
                    ChildChainIt->second.push_back(std::move(NewChild.get()));
                }
                Allocated += NewChildDesc.GetSize();
            } else {
                //Allocate a new memory page "parent" block and add it to the map, give it no children yet
                auto NewParent = m_AllocImp.AllocateMemory(m_AllowedRegion.GetStart(), m_AllowedRegion.GetEnd(),
                                                           m_AllocImp.QueryPreferedAllocSize(),
                                                           PLH::ProtFlag::R | PLH::ProtFlag::W);
                if (NewParent) {
                    m_ParentChildMap.insert({NewParent.get(), std::vector<PLH::AllocatedMemoryBlock>()});
                } else {
                    //failed to allocate new page
                    throw AllocationFailure();
                }
            }
        } while (Allocated < AllocationSize);
        std::cout << std::endl;
        return (pointer)ChildChainIt->first.GetDescription().GetStart();
    }

    /*********************************************************************************************************************
     ** Attempts to allocate a single child block inside of any parent block. Will allocate either at the start of      **
     ** a new parent block, or at the end of an existing one, gaps are not filled. Will greedily allocate children      **
     ** into the first free space of any parent, even if the space is < DesiredSpace. Therefore, to use this            **
     ** properly the size of the returned child must be checked, and this called in loop to allocate up to DesiredSpace **
     *********************************************************************************************************************/
    boost::optional<PLH::AllocatedMemoryBlock> CreateChildInParent(
            std::vector<PLH::AllocatedMemoryBlock>& AllocatedBlocks,
            std::size_t DesiredSpace, std::size_t RequiredAlignment) {
        boost::optional<PLH::AllocatedMemoryBlock> gaurd;
        for (int i = 0; i < AllocatedBlocks.size(); i++) {
            PLH::AllocatedMemoryBlock ParentBlock = AllocatedBlocks[i];
            PLH::MemoryBlock ParentDesc = ParentBlock.GetDescription();

            auto ParentChildPair = m_ParentChildMap.find(ParentBlock);
            if (ParentChildPair == m_ParentChildMap.end())
                continue;
            std::vector<PLH::AllocatedMemoryBlock>& Children = ParentChildPair->second;

            uint64_t ChildBlockStart = 0;
            if (Children.size() == 0) {
                //Add first child
                ChildBlockStart = ParentDesc.GetStart();
            } else if (Children.size() != 0) {
                //Add successive children to end
                ChildBlockStart = Children.back().GetDescription().GetEnd();
            } else {
                continue;
            }

            /*
             * By aligning the start, we ensure that all following allocations are also aligned. This is true because
             * C/C++ guarantees object size is multiple of alignment:
             * https://stackoverflow.com/questions/4637774/is-the-size-of-a-struct-required-to-be-an-exact-multiple-of-the-alignment-of-tha
             * Range checks for possibly rounding up occur in ChildBlockEnd calculations.*/
            ChildBlockStart = (uint64_t)PLH::AlignUpwards((uint8_t*)ChildBlockStart, RequiredAlignment);
            assert(ChildBlockStart % RequiredAlignment == 0);

            uint64_t ChildBlockEnd = 0;
            if (ChildBlockStart + DesiredSpace <= ParentDesc.GetEnd()) {
                ChildBlockEnd = ChildBlockStart + DesiredSpace;
            } else if (ParentDesc.GetEnd() - ChildBlockStart > 0) {
                ChildBlockEnd = ParentDesc.GetEnd();
            } else {
                continue;
            }

            PLH::MemoryBlock NewChildDesc(ChildBlockStart, ChildBlockEnd, ParentDesc.GetProtection());
            PLH::AllocatedMemoryBlock NewChildBlock(ParentBlock.GetParentBlock(), NewChildDesc);

            Children.push_back(NewChildBlock);
            gaurd = Children.back();
            return gaurd;
        }
        return gaurd;
    }

    /*********************************************************************
     * Frees either a single child block or a chain of child blocks if the ptr we
     * are passed is the start of a chain.
     * ******************************************************************/
    void deallocate(pointer ptr, size_type n) {
        const std::size_t allocationSize = n * sizeof(value_type);
        std::size_t deAllocated = 0;
        std::vector<PLH::AllocatedMemoryBlock>::iterator childIt;


        //Figure out which chain the ptr we got is part of. And erase chain start
        for (auto& KeyValuePair : m_ParentChildMap) {
            const PLH::AllocatedMemoryBlock& ParentBlock = KeyValuePair.first;
            std::vector<PLH::AllocatedMemoryBlock>& Children = KeyValuePair.second;

            if(deAllocated >= allocationSize)
                break;

            //If it's the first run, find the chain start
            if(deAllocated == 0) {
                //Find the containing parent block
                if (!ParentBlock.GetDescription().ContainsAddress((uint64_t)ptr))
                    continue;

                //Find the block that starts the allocation chain
                auto firstChild = std::find_if(Children.begin(), Children.end(),
                                               [=](const PLH::AllocatedMemoryBlock& Child) -> bool {
                                                   return Child.GetDescription().GetStart() == (uint64_t)ptr;
                                               });

                //Erase the child to sibling mappings
                ChildSiblingMap::iterator childSiblingChainIt = m_ChildSiblingMap.find((*firstChild));
                m_ChildSiblingMap.erase(childSiblingChainIt, std::next(childSiblingChainIt));

                childIt = firstChild;
            }else{
                childIt = Children.begin();
            }

            //Remove the chain up to what's in this parent block
            while(childIt != Children.end())
            {
                if(deAllocated >= allocationSize)
                    break;

                deAllocated += childIt->GetDescription().GetSize();
                childIt = Children.erase(childIt, std::next(childIt));
            }
        }
        assert(deAllocated == allocationSize);
    }

    template<typename U>
    struct rebind
    {
        typedef RangeAllocator<U, Platform> other;
    };

    bool operator==(PLH::RangeAllocator<T, Platform> const& other) {
        return m_AllowedRegion == other.m_AllowedRegion;
    }

    bool operator!=(PLH::RangeAllocator<T, Platform> const& other) {
        return !(other == *this);
    }

    size_type max_size(void) const {
        return std::numeric_limits<size_type>::max() / sizeof(value_type);
    }

private:
    //[Start,End)
    bool IsInRange(uint64_t Address) {
        return Address >= m_AllowedRegion.GetStart() && Address < m_AllowedRegion.GetEnd();
    }

    PLH::ARangAllocator<Platform> m_AllocImp;
    PLH::MemoryBlock m_AllowedRegion;

    /* The map between larger parent blocks, and the children blocks currently allocated inside
     * of it. Key is a parent block, value is a vector of children blocks*/
    ParentChildMap m_ParentChildMap;

    /* The map between the the first child memory block for an allocation, and the child blocks chained
     * after it. The vector (value of key-value pair) can span multiple "parent" blocks. This conceptually
     * remembers which allocations had to be chained together so that de-allocation is easier. Key is a
     * child block, value is a vector of other children blocks (siblings)*/
    ChildSiblingMap m_ChildSiblingMap;
};

template<typename T, typename Platform, typename OtherAllocator>
inline bool operator==(PLH::RangeAllocator<T, Platform> const&,
                       OtherAllocator const&) {
    return false;
}
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
