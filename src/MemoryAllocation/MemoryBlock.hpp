//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "../Misc.hpp"
#include "../Enums.hpp"
#include <sstream>
namespace PLH
{
    /* ******************************************************************************************
     * This class represent a region of virtual memory. This region doesn't need to be allocated,
     * it simply handles the idea of a range of memory and the protection of that region. This
     * region is not restricted to a size of a single page, it can be any arbitrary length. It
     * also gives helper methods for alignment should it need to be aligned to page boundaries
     * *****************************************************************************************/
    class MemoryBlock
    {
    public:
        MemoryBlock(const uint64_t Start,const uint64_t End,const PLH::ProtFlag Prot);
        MemoryBlock();
        uint64_t GetStart() const;
        uint64_t GetEnd() const;
        uint64_t GetSize() const;
        PLH::ProtFlag GetProtection() const;
        std::string ToString() const;

        uint64_t GetAlignedFirstPage(const size_t Alignment,const size_t PageSize) const;
        uint64_t GetAlignedNextPage(const uint64_t CurPageStart,const size_t Alignment,const size_t PageSize) const;
        uint64_t GetAlignedPageNearestUp(const uint64_t Address,const size_t Alignment,const size_t PageSize) const;
        uint64_t GetAlignedPageNearestDown(const uint64_t Address,const size_t Alignment,const size_t PageSize) const;

        bool ContainsBlock(const PLH::MemoryBlock& other);
        bool operator ==(const PLH::MemoryBlock& other);
        bool operator !=(const PLH::MemoryBlock& other);
    private:
        bool InRange(const uint64_t Address,const size_t Size) const;
        uint64_t m_Start;
        uint64_t m_End;
        PLH::ProtFlag m_Protection;
    };

    MemoryBlock::MemoryBlock(const uint64_t Start,const uint64_t End,const PLH::ProtFlag Prot)
    {
        m_Start = Start;
        m_End = End;
        m_Protection = Prot;
    }

    MemoryBlock::MemoryBlock()
    {
        m_Start = 0;
        m_End = 0;
        m_Protection = PLH::ProtFlag::UNSET;
    }

    uint64_t MemoryBlock::GetStart() const
    {
        return m_Start;
    }

    uint64_t MemoryBlock::GetEnd() const
    {
        return m_End;
    }

    uint64_t MemoryBlock::GetSize() const
    {
        return m_End - m_Start;
    }

    PLH::ProtFlag MemoryBlock::GetProtection() const
    {
        return m_Protection;
    }

    //[Start, End]
    bool MemoryBlock::InRange(const uint64_t Address,const size_t Size) const
    {
        if(Address < m_Start || (Address + Size) > m_End)
            return false;
        return true;
    }

    uint64_t MemoryBlock::GetAlignedFirstPage(const size_t Alignment,const size_t PageSize) const
    {
        return GetAlignedPageNearestDown(m_Start,Alignment,PageSize);
    }

    //[Start, End)
    uint64_t MemoryBlock::GetAlignedNextPage(const uint64_t CurPageStart,const size_t Alignment,const size_t PageSize) const
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
    uint64_t MemoryBlock::GetAlignedPageNearestDown(const uint64_t Address,const size_t Alignment,const size_t PageSize) const
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
    uint64_t MemoryBlock::GetAlignedPageNearestUp(const uint64_t Address,const size_t Alignment,const size_t PageSize) const
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

    //[Start,End]
    bool MemoryBlock::ContainsBlock(const PLH::MemoryBlock &other)
    {
        return other.GetStart() >= m_Start && other.GetEnd() <= m_End;
    }

    std::string MemoryBlock::ToString() const
    {
        std::stringstream ss;
        ss << std::hex << "Start:" << m_Start << " End:" << m_End << " Prot:" << PLH::ProtFlagToString(m_Protection);
        return ss.str();
    }

    bool MemoryBlock::operator==(const PLH::MemoryBlock &other) {
        return m_Start == other.m_Start &&
                m_End == other.m_End;
    }

    bool MemoryBlock::operator!=(const PLH::MemoryBlock &other) {
        return !(*this == other);
    }
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
