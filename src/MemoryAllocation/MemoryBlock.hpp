//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "src/Misc.hpp"
#include "src/Enums.hpp"
#include "src/UID.hpp"
#include <sstream>
#include <boost/optional.hpp>

namespace PLH {
/* ******************************************************************************************
 * This class represent a region of virtual memory. This region doesn't need to be allocated,
 * it simply handles the idea of a range of memory and the protection of that region. This
 * region is not restricted to a size of a single page, it can be any arbitrary length. It
 * also gives helper methods for alignment should it need to be aligned to page boundaries
 * *****************************************************************************************/
class MemoryBlock
{
public:
    MemoryBlock(const uint64_t Start, const uint64_t End, const PLH::ProtFlag Prot);

    MemoryBlock();

    uint64_t GetStart() const;

    uint64_t GetEnd() const;

    uint64_t GetSize() const;

    PLH::ProtFlag GetProtection() const;

    UID id() const {
        return uid;
    }

    /**Alignment helpers that always return in range [Start, End) of MemoryBlock. Return Value is the
     * aligned address, Alignment is desired alignment, Size is the size of the region attempting
     * to be aligned. For example if we want to find the nearest memory page to an address with an alignment
     * of 4 bytes, and we also what to ensure the aligned page address is > Address:
     * GetAlignedNearestUp(Address, 4, 4096) where 4096 is the size of a single page.**/
    boost::optional<uint64_t> GetAlignedFirst(const size_t Alignment, const size_t Size) const;

    boost::optional<uint64_t> GetAlignedNext(const uint64_t Address, const size_t Alignment, const size_t Size) const;

    boost::optional<uint64_t>
    GetAlignedNearestUp(const uint64_t Address, const size_t Alignment, const size_t Size) const;

    boost::optional<uint64_t>
    GetAlignedNearestDown(const uint64_t Address, const size_t Alignment, const size_t Size) const;

    bool ContainsBlock(const PLH::MemoryBlock& other) const;

    bool ContainsAddress(const uint64_t Address) const;

    bool operator==(const PLH::MemoryBlock& other) const;

    bool operator!=(const PLH::MemoryBlock& other) const;

    bool operator<(const PLH::MemoryBlock& other) const;

    bool operator>(const PLH::MemoryBlock& other) const;

    bool operator<=(const PLH::MemoryBlock& other) const;

    bool operator>=(const PLH::MemoryBlock& other) const;

private:
    bool InRange(const uint64_t Address, const size_t Size) const;

    uint64_t      m_Start;
    uint64_t      m_End;
    PLH::ProtFlag m_Protection;
    UID           uid;
};

MemoryBlock::MemoryBlock(const uint64_t Start, const uint64_t End, const PLH::ProtFlag Prot) {
    m_Start      = Start;
    m_End        = End;
    m_Protection = Prot;
}

MemoryBlock::MemoryBlock() {
    m_Start      = 0;
    m_End        = 0;
    m_Protection = PLH::ProtFlag::UNSET;
}

uint64_t MemoryBlock::GetStart() const {
    return m_Start;
}

uint64_t MemoryBlock::GetEnd() const {
    return m_End;
}

uint64_t MemoryBlock::GetSize() const {
    return m_End - m_Start;
}

PLH::ProtFlag MemoryBlock::GetProtection() const {
    return m_Protection;
}

//[Start, End]
bool MemoryBlock::InRange(const uint64_t Address, const size_t Size) const {
    return Address >= m_Start && (Address + Size) <= m_End;
}

boost::optional<uint64_t> MemoryBlock::GetAlignedFirst(const size_t Alignment, const size_t Size) const {
    if (auto Aligned = GetAlignedNearestDown(m_Start, Alignment, Size))
        return Aligned;
    return GetAlignedNearestUp(m_Start, Alignment, Size);
}

//[Start, End)
boost::optional<uint64_t>
MemoryBlock::GetAlignedNext(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    boost::optional<uint64_t> AlignedAddress;
    assert(Size > 0);
    assert(Alignment > 0);

    /* Next address is address + size, verify it follows alignment, if the entire 'next'
     * region doesn't fit in our MemoryBlock then return null, otherwise the address*/
    uint64_t Next = Address + Size;
    assert(Next > Address && "Check block boundary alignment next");
    assert(Next + Size > Next && "Check for wrap-around");
    assert(Next % Alignment == 0);
    if (!InRange(Next, Size))
        return AlignedAddress;

    AlignedAddress = Next;
    return AlignedAddress;
}

//[Start, End)
boost::optional<uint64_t>
MemoryBlock::GetAlignedNearestDown(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    boost::optional<uint64_t> AlignedAddress;
    assert(Size > 0);
    assert(Alignment > 0);

    uint64_t NearestDown = (uint64_t)PLH::AlignDownwards((uint8_t*)Address, Alignment);
    if (!InRange(NearestDown, Size))
        return AlignedAddress;

    assert(NearestDown <= Address && "Check block boundary alignment down");
    assert(NearestDown % Alignment == 0);
    AlignedAddress = NearestDown;
    return AlignedAddress;
}

//[Start, End)
boost::optional<uint64_t>
MemoryBlock::GetAlignedNearestUp(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    boost::optional<uint64_t> AlignedAddress;
    assert(Size > 0);
    assert(Alignment > 0);

    uint64_t NearestUp = (uint64_t)PLH::AlignUpwards((uint8_t*)Address, Alignment);
    if (!InRange(NearestUp, Size))
        return AlignedAddress;

    assert(NearestUp >= Address && "Check block boundary alignment up");
    assert(NearestUp % Alignment == 0);
    AlignedAddress = NearestUp;
    return AlignedAddress;
}

//[Start,End]
bool MemoryBlock::ContainsBlock(const PLH::MemoryBlock& other) const {
    return other.GetStart() >= this->GetStart() && other.GetEnd() <= this->GetEnd();
}

//[Start,End)
bool MemoryBlock::ContainsAddress(const uint64_t Address) const {
    return this->GetStart() <= Address && Address < this->GetEnd();
}

std::ostream& operator<<(std::ostream& os, const MemoryBlock& obj) {
    os << std::hex << "[" << obj.GetStart() << "-" << obj.GetEnd() << ")" << std::dec
       << PLH::ProtFlagToString(obj.GetProtection());
    return os;
}

bool MemoryBlock::operator==(const PLH::MemoryBlock& other) const {
    return this->GetStart() == other.GetStart() &&
           this->GetEnd() == other.GetEnd();
}

bool MemoryBlock::operator!=(const PLH::MemoryBlock& other) const {
    return !(*this == other);
}

bool MemoryBlock::operator>(const PLH::MemoryBlock& other) const {
    //end is exclusive so others end can == others' start
    return this->GetStart() >= other.GetEnd();
}

bool MemoryBlock::operator<(const PLH::MemoryBlock& other) const {
    //end is exclusive so our end can == other's start
    return this->GetEnd() <= other.GetStart();
}

bool MemoryBlock::operator<=(const PLH::MemoryBlock& other) const {
    return *this < other || *this == other;
}

bool MemoryBlock::operator>=(const PLH::MemoryBlock& other) const {
    return *this > other || *this == other;
}
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
