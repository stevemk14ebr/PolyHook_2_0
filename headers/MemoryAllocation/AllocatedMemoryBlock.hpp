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
    AllocatedMemoryBlock(std::shared_ptr<char> parentBlock, PLH::MemoryBlock ourDesc) :
            m_parentBlock(std::move(parentBlock)), m_ourDesc(ourDesc) {

    }

    //delegate constructors allowed in c++11
    AllocatedMemoryBlock(std::shared_ptr<char> parentBlock, uint64_t start, uint64_t end, PLH::ProtFlag protection) :
            AllocatedMemoryBlock(std::move(parentBlock), PLH::MemoryBlock(start, end, protection)) {

    }

    AllocatedMemoryBlock() : m_parentBlock(std::shared_ptr<char>()),
                             m_ourDesc(PLH::MemoryBlock()) {

    }

    std::shared_ptr<char> getParentBlock() const {
        return m_parentBlock;
    }

    uint64_t getSize() const {
        return m_ourDesc.getSize();
    }

    PLH::MemoryBlock getDescription() const {
        return m_ourDesc;
    }

    UID id() const {
        return m_uid;
    }

    bool containsBlock(const PLH::MemoryBlock& other) const;

    bool containsBlock(const PLH::AllocatedMemoryBlock& other) const;

    explicit operator PLH::MemoryBlock() const;

    bool operator==(const AllocatedMemoryBlock& other) const;

    bool operator!=(const AllocatedMemoryBlock& other) const;

    bool operator<(const AllocatedMemoryBlock& other) const;

    bool operator>(const AllocatedMemoryBlock& other) const;

    bool operator>=(const AllocatedMemoryBlock& other) const;

    bool operator<=(const AllocatedMemoryBlock* other) const;

private:
    std::shared_ptr<char> m_parentBlock;
    PLH::MemoryBlock      m_ourDesc;
    UID                   m_uid;
};
}
#endif
