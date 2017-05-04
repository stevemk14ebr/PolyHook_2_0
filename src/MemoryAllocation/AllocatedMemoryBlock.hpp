//
// Created by steve on 4/27/17.
//
#ifndef POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP
#define POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP
#include "MemoryBlock.hpp"
#include <memory>
namespace PLH
{
    /* This is a "Chunk" of allocated virtual memory, this object exists to split a real system memory page into usable,
     * smaller chunks. It holds 3 things, a pointer to the parent, a description of that region, and a description of our
     * sub-region inside that parent region.
     *
     * Each allocated region contains a shared_ptr to it's parent region. This is because shared_ptrs are ref counted.
     * By storing a reference to the parent we make sure our region (which is a sub-region of the parent) is still valid by at
     * least haveing a reference of one at all times.
     * Only once all AllocatedMemoryBlock objects are destroyed is the parent region freed by the shared_ptr's deleter
     */
    class AllocatedMemoryBlock
    {
    public:
        AllocatedMemoryBlock(PLH::MemoryBlock ParentBlockDesc, std::shared_ptr<uint8_t> ParentBlock, PLH::MemoryBlock OurDesc) :
                m_ParentBlockDesc(ParentBlockDesc), m_ParentBlock(ParentBlock), m_OurDesc(OurDesc)
        {
            assert(m_ParentBlockDesc.ContainsBlock(OurDesc) && "Parent blocks must contain full range of child");
        }

        //delegate constructors allowed in c++11
        AllocatedMemoryBlock(PLH::MemoryBlock ParentBlockDesc, std::shared_ptr<uint8_t> ParentBlock, uint64_t Start, uint64_t End) :
                AllocatedMemoryBlock(ParentBlockDesc,ParentBlock, PLH::MemoryBlock(Start,End,m_ParentBlockDesc.GetProtection()))
        {

        }

        AllocatedMemoryBlock() : m_ParentBlock(std::shared_ptr<uint8_t>()), m_ParentBlockDesc(PLH::MemoryBlock()),
                                 m_OurDesc(PLH::MemoryBlock())
        {

        }

        std::shared_ptr<uint8_t> GetParentBlock() const
        {
            return m_ParentBlock;
        }

        uint64_t GetSize() const
        {
            return m_OurDesc.GetSize();
        }

        bool ContainsBlock(const PLH::MemoryBlock& other);
        bool ContainsBlock(const PLH::AllocatedMemoryBlock& other);

        bool operator==(const AllocatedMemoryBlock& other);
        bool operator!=(const AllocatedMemoryBlock& other);
        std::string ToString();
    private:
        //TO-DO: Determine if ParentBlockDesc is necessary info to store
        std::shared_ptr<uint8_t> m_ParentBlock;
        PLH::MemoryBlock m_ParentBlockDesc;
        PLH::MemoryBlock m_OurDesc;
    };

    bool AllocatedMemoryBlock::operator==(const AllocatedMemoryBlock &other) {
        return (m_ParentBlock.get() == other.m_ParentBlock.get()) &&
                m_ParentBlockDesc == other.m_ParentBlockDesc &&
                m_OurDesc == other.m_OurDesc;
    }

    bool AllocatedMemoryBlock::operator!=(const AllocatedMemoryBlock &other) {
        return !(*this == other);
    }

    bool AllocatedMemoryBlock::ContainsBlock(const PLH::MemoryBlock &other) {
        return m_OurDesc.ContainsBlock(other);
    }

    bool AllocatedMemoryBlock::ContainsBlock(const PLH::AllocatedMemoryBlock &other) {
        return m_OurDesc.ContainsBlock(other.m_OurDesc);
    }
}
#endif
