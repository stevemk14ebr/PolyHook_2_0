//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/MemoryBlock.hpp"

PLH::MemoryBlock::MemoryBlock(const uint64_t Start, const uint64_t End, const PLH::ProtFlag Prot) {
    m_Start      = Start;
    m_End        = End;
    m_Protection = Prot;
}

PLH::MemoryBlock::MemoryBlock() {
    m_Start      = 0;
    m_End        = 0;
    m_Protection = PLH::ProtFlag::UNSET;
}

uint64_t PLH::MemoryBlock::GetStart() const {
    return m_Start;
}

uint64_t PLH::MemoryBlock::GetEnd() const {
    return m_End;
}

uint64_t PLH::MemoryBlock::GetSize() const {
    return m_End - m_Start;
}

PLH::ProtFlag PLH::MemoryBlock::GetProtection() const {
    return m_Protection;
}

//[Start, End]
bool PLH::MemoryBlock::InRange(const uint64_t Address, const size_t Size) const {
    return Address >= m_Start && (Address + Size) <= m_End;
}

PLH::Maybe<uint64_t> PLH::MemoryBlock::GetAlignedFirst(const size_t Alignment, const size_t Size) const {
    if (auto Aligned = GetAlignedNearestDown(m_Start, Alignment, Size))
        return Aligned;
    return GetAlignedNearestUp(m_Start, Alignment, Size);
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::GetAlignedNext(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    assert(Size > 0);
    assert(Alignment > 0);

    /* Next address is address + size, verify it follows alignment, if the entire 'next'
     * region doesn't fit in our MemoryBlock then return null, otherwise the address*/
    uint64_t Next = Address + Size;
    assert(Next > Address && "Check block boundary alignment next");
    assert(Next + Size > Next && "Check for wrap-around");
    assert(Next % Alignment == 0);
    if (!InRange(Next, Size))
        function_fail("Address not in range after alignment");

    return Next;
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::GetAlignedNearestDown(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    assert(Size > 0);
    assert(Alignment > 0);

    uint64_t NearestDown = (uint64_t)PLH::AlignDownwards((uint8_t*)Address, Alignment);
    if (!InRange(NearestDown, Size))
        function_fail("Address not in range after alignment");

    assert(NearestDown <= Address && "Check block boundary alignment down");
    assert(NearestDown % Alignment == 0);
    return NearestDown;
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::GetAlignedNearestUp(const uint64_t Address, const size_t Alignment, const size_t Size) const {
    assert(Size > 0);
    assert(Alignment > 0);

    uint64_t NearestUp = (uint64_t)PLH::AlignUpwards((uint8_t*)Address, Alignment);
    if (!InRange(NearestUp, Size))
        function_fail("Address not in range after alignment");

    assert(NearestUp >= Address && "Check block boundary alignment up");
    assert(NearestUp % Alignment == 0);
    return NearestUp;
}

//[Start,End]
bool PLH::MemoryBlock::ContainsBlock(const PLH::MemoryBlock& other) const {
    return other.GetStart() >= this->GetStart() && other.GetEnd() <= this->GetEnd();
}

//[Start,End)
bool PLH::MemoryBlock::ContainsAddress(const uint64_t Address) const {
    return this->GetStart() <= Address && Address < this->GetEnd();
}

bool PLH::MemoryBlock::operator==(const PLH::MemoryBlock& other) const {
    return this->GetStart() == other.GetStart() &&
           this->GetEnd() == other.GetEnd();
}

bool PLH::MemoryBlock::operator!=(const PLH::MemoryBlock& other) const {
    return !(*this == other);
}

bool PLH::MemoryBlock::operator>(const PLH::MemoryBlock& other) const {
    //end is exclusive so others end can == others' start
    return this->GetStart() >= other.GetEnd();
}

bool PLH::MemoryBlock::operator<(const PLH::MemoryBlock& other) const {
    //end is exclusive so our end can == other's start
    return this->GetEnd() <= other.GetStart();
}

bool PLH::MemoryBlock::operator<=(const PLH::MemoryBlock& other) const {
    return *this < other || *this == other;
}

bool PLH::MemoryBlock::operator>=(const PLH::MemoryBlock& other) const {
    return *this > other || *this == other;
}

