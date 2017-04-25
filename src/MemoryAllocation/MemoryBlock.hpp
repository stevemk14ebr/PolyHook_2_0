//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "../Misc.hpp"
#include "../Enums.hpp"
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
        std::string ToString();

        uint64_t GetAlignedFirstPage(size_t Alignment, size_t PageSize);
        uint64_t GetAlignedNextPage(uint64_t CurPageStart,size_t Alignment,size_t PageSize);
        uint64_t GetAlignedPageNearestUp(uint64_t Address, size_t Alignment, size_t PageSize);
        uint64_t GetAlignedPageNearestDown(uint64_t Address, size_t Alignment, size_t PageSize);
    private:
        bool InRange(uint64_t Address, size_t Size);
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

    //[Start, End)
    bool MemoryBlock::InRange(uint64_t Address,size_t Size)
    {
        if(Address < m_Start || (Address + Size) > m_End)
            return false;
        return true;
    }

    uint64_t MemoryBlock::GetAlignedFirstPage(size_t Alignment,size_t PageSize)
    {
        return GetAlignedPageNearestDown(m_Start,Alignment,PageSize);
    }

    //[Start, End)
    uint64_t MemoryBlock::GetAlignedNextPage(uint64_t CurPageStart, size_t Alignment,size_t PageSize)
    {
        assert(PageSize > 0);
        /* Next page is curpage + pagesize, verify it follows alignment, if the entire 'next'
         * page doesn't fit in our MemoryBlock then return null, otherwise the page*/
        uint64_t Next = CurPageStart + PageSize;
        assert(Next % Alignment == 0);
        assert(Next + PageSize > Next && "Check for wrap-around");
        if(!InRange(Next,PageSize))
            return NULL;
        return Next;
    }

    //[Start, End)
    uint64_t MemoryBlock::GetAlignedPageNearestDown(uint64_t Address, size_t Alignment, size_t PageSize)
    {
        uint64_t NearestDown = (uint64_t)PLH::AlignDownwards((uint8_t*)Address,Alignment);
        while(!InRange(NearestDown,PageSize)) //loop required since address could be = m_Start
        {
            NearestDown += PageSize;
            if(NearestDown >= m_End)
                return NULL;
        }
        assert(NearestDown % Alignment == 0);
        return NearestDown;
    }

    //[Start, End)
    uint64_t MemoryBlock::GetAlignedPageNearestUp(uint64_t Address, size_t Alignment, size_t PageSize)
    {
        uint64_t NearestUp = (uint64_t)PLH::AlignUpwards((uint8_t*)Address,Alignment);
        while(!InRange(NearestUp,PageSize)) //loop required for case address = m_End
        {
            NearestUp -= PageSize;
            if(NearestUp < m_Start)
                return NULL;
        }
        assert(NearestUp % Alignment == 0);
        return NearestUp;
    }

    std::string MemoryBlock::ToString()
    {
        std::stringstream ss;
        ss << std::hex << "Start:" << m_Start << " End:" << m_End << " Prot:" << PLH::ProtFlagToString(m_Protection);
        return ss.str();
    }
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
