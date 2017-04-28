//
// Created by steve on 4/27/17.
//
#include "MemoryBlock.hpp"
#include <memory>
namespace PLH
{
    class AllocatedMemoryBlock
    {
    public:
        uint64_t GetStart()
        {
            m_Block.GetStart();
        }

        uint64_t GetEnd()
        {
            m_Block.GetEnd();
        }

    private:
        std::shared_ptr<uint8_t> m_AllocatedBlock;
        PLH::MemoryBlock m_Block;
    };
}
