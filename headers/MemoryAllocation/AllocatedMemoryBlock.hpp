//
// Created by steve on 4/27/17.
//
#ifndef POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP
#define POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP

#include "headers/MemoryAllocation/MemoryBlock.hpp"
#include "headers/UID.hpp"
#include <memory>


namespace PLH {
/* This is a "Chunk" of allocated virtual memory, this object exists to split a real system memory page into usable,
 * smaller chunks. It holds 3 things, a pointer to the parent, a description of that region, and a description of our
 * sub-region inside that parent region.
 *
 * Each allocated region contains a shared_ptr to it's parent region. This is because shared_ptrs are ref counted.
 * By storing a reference to the parent we make sure our region (which is a sub-region of the parent) is still valid by at
 * least having a reference count of one at all times to the parent.
 * Only once all AllocatedMemoryBlock objects are destroyed is the parent region freed by the shared_ptr's deleter
 */
class AllocatedMemoryBlock
{
public:
    AllocatedMemoryBlock(std::shared_ptr<char> ParentBlock, PLH::MemoryBlock OurDesc) : m_ParentBlock(std::move(
            ParentBlock)),
                                                                                        m_OurDesc(OurDesc) {

    }

    //delegate constructors allowed in c++11
    AllocatedMemoryBlock(std::shared_ptr<char> ParentBlock, uint64_t Start, uint64_t End, PLH::ProtFlag Protection) :
            AllocatedMemoryBlock(std::move(ParentBlock), PLH::MemoryBlock(Start, End, Protection)) {

    }

    AllocatedMemoryBlock() : m_ParentBlock(std::shared_ptr<char>()),
                             m_OurDesc(PLH::MemoryBlock()) {

    }

    std::shared_ptr<char> GetParentBlock() const {
        return m_ParentBlock;
    }

    uint64_t GetSize() const {
        return m_OurDesc.GetSize();
    }

    PLH::MemoryBlock GetDescription() const {
        return m_OurDesc;
    }

    UID id() const {
        return uid;
    }

    bool ContainsBlock(const PLH::MemoryBlock& other) const;

    bool ContainsBlock(const PLH::AllocatedMemoryBlock& other) const;

    explicit operator PLH::MemoryBlock() const;

    bool operator==(const AllocatedMemoryBlock& other) const;

    bool operator!=(const AllocatedMemoryBlock& other) const;

    bool operator<(const AllocatedMemoryBlock& other) const;

    bool operator>(const AllocatedMemoryBlock& other) const;

    bool operator>=(const AllocatedMemoryBlock& other) const;

    bool operator<=(const AllocatedMemoryBlock* other) const;

private:
    std::shared_ptr<char> m_ParentBlock;
    PLH::MemoryBlock      m_OurDesc;
    UID                   uid;
};
}
#endif
