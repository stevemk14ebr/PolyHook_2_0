//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "Enums.hpp"
namespace PLH
{
    //Not necessarily a memory page, just a range of virtual memory
    class MemoryBlock
    {
    public:
        MemoryBlock(uint64_t Start, uint64_t End, PLH::ProtFlag Prot);
        uint64_t GetStart();
        uint64_t GetEnd();
        PLH::ProtFlag GetProtection();
        size_t CountPagesInBlock(size_t PageSize);
        std::string ToString();
    private:
        uint64_t m_Start;
        uint64_t m_End;
        PLH::ProtFlag m_Protection;
    };

    MemoryBlock::MemoryBlock(uint64_t Start, uint64_t End, PLH::ProtFlag Prot)
    {
        m_Start = Start;
        m_End = End;
        m_Protection = Prot;
    }

    uint64_t MemoryBlock::GetStart()
    {
        return m_Start;
    }

    uint64_t MemoryBlock::GetEnd()
    {
        return m_End;
    }

    PLH::ProtFlag MemoryBlock::GetProtection()
    {
        return m_Protection;
    }

    size_t MemoryBlock::CountPagesInBlock(size_t PageSize)
    {
        return (m_End - m_Start) / PageSize;
    }

    std::string MemoryBlock::ToString()
    {
        std::stringstream ss;
        ss << std::hex << "Start:" << m_Start << " End:" << m_End << " Prot:" << PLH::ProtFlagToString(m_Protection);
        return ss.str();
    }
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
