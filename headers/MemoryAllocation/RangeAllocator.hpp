//
// Created by steve on 4/25/17.
//

#ifndef POLYHOOK_2_0_MEMORYALLOCATOR_HPP
#define POLYHOOK_2_0_MEMORYALLOCATOR_HPP

#include <memory>
#include <map>
#include <type_traits>
#include <algorithm>
#include "headers/MemoryAllocation/ARangAllocator.hpp"

//General Allocator Design: https://www.youtube.com/watch?v=LIb3L4vKZ7U
//Design Inspiration: http://jrruethe.github.io/blog/2015/11/22/allocators/
namespace PLH {
/******************************************************************************************************
**  This class handles actually splitting AllocatedMemoryBlocks into smaller AllocatedMemoryBlocks and
**  then serving the smaller chunks up to whatever uses the allocator. It deals with the mapping of
**  larger "Parent" blocks to all of the parent's "Children" blocks via a map. This follows the
**  first fit allocation algorithm with address ordering. This means it allocates at the lower addresses
**  first towards the higher addresses.
 *
 * **THIS IS NOT A THREAD SAFE CLASS, ANY CLASS THAT USES THIS MUST HAVE SEPERATE LOGIC TO HANDLE THIS*
 * ^See parentchildmap member comment's below for reason why
******************************************************************************************************/
template<class T, class Platform>
class RangeAllocator
{
public:
    typedef T value_type;
    typedef value_type      * pointer;
    typedef const value_type* const_pointer;
    typedef value_type      & reference;
    typedef const value_type& const_reference;
    typedef std::size_t    size_type;
    typedef std::ptrdiff_t difference_type;

    typedef std::map<PLH::AllocatedMemoryBlock, std::vector<PLH::AllocatedMemoryBlock>>
            ParentChildMap;

    RangeAllocator(uint64_t min, uint64_t max) : m_parentChildMap(new ParentChildMap) {
        m_allowedRegion = PLH::MemoryBlock(min, max, PLH::UNSET);
    }

    pointer allocate(size_type count, const_pointer = 0) {
        assert(m_parentChildMap != nullptr);

        const std::size_t AllocationSize  = count * sizeof(value_type);
        const std::size_t NeededAlignment = std::alignment_of<value_type>::value;
        std::size_t       Allocated       = 0;

        std::vector<PLH::AllocatedMemoryBlock> AllocatedBlocks;
        std::vector<PLH::AllocatedMemoryBlock> Chain;
        std::vector<std::vector<UID::Value>>   FailedChains;
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
        do {
            AllocatedBlocks = m_allocImp.getAllocatedBlocks();
            auto NewChild   = CreateChildInParent(AllocatedBlocks, AllocationSize - Allocated, NeededAlignment);
            if (NewChild) {
                PLH::MemoryBlock NewChildDesc = NewChild.unwrap().getDescription();
                Allocated += NewChildDesc.getSize();
                Chain.push_back(NewChild.unwrap());

                //Verify blocks are contiguous, if not then de-allocate and re-try
                if (Chain.size() > 1) {
                    uint64_t prevBlockEnd  = std::prev(Chain.end() - 1)->getDescription().getEnd();
                    uint64_t newBlockStart = NewChildDesc.getStart();

                    //chain not contiguous, store it to free later, re-try
                    if (prevBlockEnd != newBlockStart) {
                        //Transform into an array of uids
                        std::vector<UID::Value> chainUIDs;
                        std::transform(Chain.begin(),
                                       Chain.end(),
                                       std::back_inserter(chainUIDs),
                                       [](const PLH::AllocatedMemoryBlock& block) {
                                           return block.id().value();
                                       });
                        FailedChains.push_back(chainUIDs);

                        Allocated = 0;
                        Chain.clear();
                        continue;
                    }
                }
                continue; //Only make a parent block if child allocation failed
            }

            //Allocate a new memory page "parent" block and add it to the map, give it no children yet
            auto NewParent = m_allocImp.allocateMemory(m_allowedRegion.getStart(), m_allowedRegion.getEnd(),
                                                       m_allocImp.queryPrefferedAllocSize(),
                                                       PLH::ProtFlag::R | PLH::ProtFlag::W | PLH::ProtFlag::X);
            if (!NewParent) {
                throw AllocationFailure();
            }
            m_parentChildMap->insert({NewParent.unwrap(), std::vector<PLH::AllocatedMemoryBlock>()});
        } while (Allocated < AllocationSize);

        //De-allocate failed chains
        for (const auto& failedChain : FailedChains) {
            deallocate_impl(failedChain);
        }

        //chain start is the address of the first block in the chain
        assert(Chain.size() >= 1);
        return (pointer)Chain[0].getDescription().getStart();
    }

    /*********************************************************************************************************************
     ** Attempts to allocate a single child block inside of any parent block. Will allocate either at the start of      **
     ** a new parent block, or at the end of an existing one, gaps are not filled. Will greedily allocate children      **
     ** into the first free space of any parent, even if the space is < DesiredSpace. Therefore, to use this            **
     ** properly the size of the returned child must be checked, and this called in loop to allocate up to DesiredSpace **
     *********************************************************************************************************************/
    PLH::Maybe<PLH::AllocatedMemoryBlock> CreateChildInParent(
            std::vector<PLH::AllocatedMemoryBlock>& allocatedBlocks,
            std::size_t desiredSpace, std::size_t requiredAlignment) {

        for (int i = 0; i < allocatedBlocks.size(); i++) {
            PLH::AllocatedMemoryBlock ParentBlock = allocatedBlocks[i];
            PLH::MemoryBlock          ParentDesc  = ParentBlock.getDescription();

            auto ParentChildPair = m_parentChildMap->find(ParentBlock);
            if (ParentChildPair == m_parentChildMap->end())
                continue;
            std::vector<PLH::AllocatedMemoryBlock>& Children = ParentChildPair->second;

            uint64_t ChildBlockStart = 0;
            if (Children.size() == 0) {
                //Add first child
                ChildBlockStart = ParentDesc.getStart();
            } else if (Children.size() != 0) {
                //Add successive children to end
                ChildBlockStart = Children.back().getDescription().getEnd();
            } else {
                continue;
            }

            /*
             * By aligning the start, we ensure that all following allocations are also aligned. This is true because
             * C/C++ guarantees object size is multiple of alignment:
             * https://stackoverflow.com/questions/4637774/is-the-size-of-a-struct-required-to-be-an-exact-multiple-of-the-alignment-of-tha
             * Range checks for possibly rounding up occur in ChildBlockEnd calculations.*/
            ChildBlockStart = (uint64_t)PLH::AlignUpwards((char*)ChildBlockStart, requiredAlignment);
            assert(ChildBlockStart % requiredAlignment == 0);

            uint64_t ChildBlockEnd = 0;
            if (ChildBlockStart + desiredSpace < ParentDesc.getEnd()) {
                ChildBlockEnd = ChildBlockStart + desiredSpace;
            } else if (ParentDesc.getEnd() - ChildBlockStart > 0) {
                ChildBlockEnd = ParentDesc.getEnd();
            } else {
                continue;
            }

            PLH::MemoryBlock          NewChildDesc(ChildBlockStart, ChildBlockEnd, ParentDesc.getProtection());
            PLH::AllocatedMemoryBlock NewChildBlock(ParentBlock.getParentBlock(), NewChildDesc);

            Children.push_back(NewChildBlock);
            return std::move(Children.back());
        }
        function_fail("Unable to allocate child");
    }

    /*********************************************************************
     * Frees either a single child block or a chain of child blocks if the ptr we
     * are passed is the start of a chain. Builds up the uids of the chain, then
     * calls the implementation to do the freeing
     * ******************************************************************/
    void deallocate(pointer ptr, size_type n) {
        const std::size_t allocationSize = n * sizeof(value_type);
        PLH::MemoryBlock  deallocationRegion((uint64_t)ptr, (uint64_t)ptr + allocationSize, PLH::ProtFlag::UNSET);

        size_t                                           deAllocationBlocks = 0;
        std::vector<PLH::AllocatedMemoryBlock>::iterator childIt;

        std::vector<UID::Value> uidsToFree;
        for (auto& KeyValuePair : *m_parentChildMap) {
            const PLH::AllocatedMemoryBlock       & parentBlock = KeyValuePair.first;
            std::vector<PLH::AllocatedMemoryBlock>& children    = KeyValuePair.second;

            if (deAllocationBlocks >= allocationSize)
                break;

            //If it's the first run, find the chain start
            if (deAllocationBlocks == 0) {
                //Find the containing parent block
                if (!parentBlock.getDescription().containsAddress((uint64_t)ptr))
                    continue;

                //Find the block that starts the allocation chain
                auto firstChild = std::find_if(children.begin(), children.end(),
                                               [=](const PLH::AllocatedMemoryBlock& Child) -> bool {
                                                   return Child.getDescription().getStart() == (uint64_t)ptr;
                                               });

                childIt = firstChild;
            } else {
                childIt = children.begin();
            }

            //Add the chains uids to the vector
            while (childIt != children.end()) {
                if (deAllocationBlocks >= allocationSize)
                    break;

                deAllocationBlocks += childIt->getDescription().getSize();
                uidsToFree.push_back(childIt->id().value());
                std::advance(childIt, 1);
            }
        }
        assert(deAllocationBlocks == allocationSize);

        //Remove all the uids
        deallocate_impl(uidsToFree);
    }

    /**Free Allocated memory blocks with some uid. Removes things
     * from the ParentChildMap, once the reference counter of the
     * shared_ptrs hits zero the memory gets freed. **/
    void deallocate_impl(const std::vector<UID::Value>& blockUIDs) {
        assert(m_parentChildMap != nullptr);
        std::vector<UID::Value> uidsLeftToFree = blockUIDs;

        for (auto& KeyValuePair : *m_parentChildMap) {
            std::vector<PLH::AllocatedMemoryBlock>& Children = KeyValuePair.second;

            if (uidsLeftToFree.size() == 0)
                break;

            //Remove the blocks in this parent that have uids we want to remove
            Children.erase(std::remove_if(Children.begin(),
                                          Children.end(),
                                          [&](const PLH::AllocatedMemoryBlock& Child) {
                                              auto iterator = std::find(uidsLeftToFree.begin(),
                                                                        uidsLeftToFree.end(),
                                                                        Child.id().value());
                                              if (iterator == uidsLeftToFree.end())
                                                  return false;

                                              //We've removed the block, remove its uid from the list
                                              uidsLeftToFree.erase(iterator);
                                              return true;
                                          }), Children.end());
        }
        //Check that we got them all
        assert(uidsLeftToFree.size() == 0);
    }

    template<typename U>
    struct rebind
    {
        typedef RangeAllocator<U, Platform> other;
    };

    bool operator==(PLH::RangeAllocator<T, Platform> const& other) {
        return m_allowedRegion == other.m_allowedRegion;
    }

    bool operator!=(PLH::RangeAllocator<T, Platform> const& other) {
        return !(other == *this);
    }

    //TODO: find a more appropriate value for this
    size_type max_size(void) const {
        return std::numeric_limits<size_type>::max() / sizeof(value_type);
    }

private:
    //[Start,End)
    bool isInRange(uint64_t address) {
        return address >= m_allowedRegion.getStart() && address < m_allowedRegion.getEnd();
    }

    PLH::ARangAllocator<Platform> m_allocImp;
    PLH::MemoryBlock              m_allowedRegion;

    /* The map between larger parent blocks, and the children blocks currently allocated inside
     * of it. Key is a parent block, value is a vector of children blocks*. This is
     * a shared_ptr because the standard requires allocatores to share their state
     * after being copied. So all copies point to the same map of blocks. This
     * also means this allocator is not thread-safe*/
    std::shared_ptr<ParentChildMap> m_parentChildMap;
};

template<typename T, typename Platform, typename OtherAllocator>
inline bool operator==(PLH::RangeAllocator<T, Platform> const&,
                       OtherAllocator const&) {
    return false;
}
}
#endif //POLYHOOK_2_0_MEMORYALLOCATOR_HPP
