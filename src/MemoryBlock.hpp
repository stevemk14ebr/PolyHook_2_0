//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "Misc.hpp"
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

        uint64_t GetAlignedFirstPage(size_t Alignment);
        uint64_t GetAlignedNextPage(uint64_t CurPageStart,size_t PageSize,size_t Alignment);
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

    uint64_t MemoryBlock::GetAlignedFirstPage(size_t Alignment)
    {
        return (uint64_t)PLH::AlignUpwards((uint8_t*)m_Start,Alignment);
    }

    uint64_t MemoryBlock::GetAlignedNextPage(uint64_t CurPageStart, size_t PageSize, size_t Alignment)
    {
        assert(PageSize > 0);
        /* Next page is curpage + pagesize, verify it follows alignment, if the entire 'next'
         * page doesn't fit in our MemoryBlock then return null, otherwise the page*/
        uint64_t Next = CurPageStart + PageSize;
        assert(Next % Alignment == 0);
        assert(Next + PageSize > Next && "Check for wrap-around");
        if(Next + PageSize > m_End)
            return NULL;
        return Next;
    }

    std::string MemoryBlock::ToString()
    {
        std::stringstream ss;
        ss << std::hex << "Start:" << m_Start << " End:" << m_End << " Prot:" << PLH::ProtFlagToString(m_Protection);
        return ss.str();
    }
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
