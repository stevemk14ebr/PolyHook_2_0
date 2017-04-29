//
// Created by steve on 4/27/17.
//
#ifndef POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP
#define POLYHOOK_2_0_ALLOCATEDMEMORYBLOCK_HPP
#include "MemoryBlock.hpp"
#include <memory>
namespace PLH
{
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

        std::shared_ptr<uint8_t> m_ParentBlock;
        PLH::MemoryBlock m_ParentBlockDesc;
        PLH::MemoryBlock m_OurDesc;
    };
}
#endif
