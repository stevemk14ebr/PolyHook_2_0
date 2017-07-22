//
// Created by steve on 7/5/17.
//
#include "headers/MemoryAllocation/MemoryBlock.hpp"

PLH::MemoryBlock::MemoryBlock(const uint64_t start, const uint64_t end, const PLH::ProtFlag prot) {
    m_start      = start;
    m_end        = end;
    m_protection = prot;
}

PLH::MemoryBlock::MemoryBlock() {
    m_start      = 0;
    m_end        = 0;
    m_protection = PLH::ProtFlag::UNSET;
}

uint64_t PLH::MemoryBlock::getStart() const {
    return m_start;
}

uint64_t PLH::MemoryBlock::getEnd() const {
    return m_end;
}

uint64_t PLH::MemoryBlock::getSize() const {
    return m_end - m_start;
}

PLH::ProtFlag PLH::MemoryBlock::getProtection() const {
    return m_protection;
}

//[Start, End]
bool PLH::MemoryBlock::inRange(const uint64_t address, const size_t size) const {
    return address >= m_start && (address + size) <= m_end;
}

PLH::Maybe<uint64_t> PLH::MemoryBlock::getAlignedFirst(const size_t alignment, const size_t size) const {
    if (auto Aligned = getAlignedNearestDown(m_start, alignment, size))
        return Aligned;
    return getAlignedNearestUp(m_start, alignment, size);
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::getAlignedNext(const uint64_t address, const size_t alignment, const size_t size) const {
    assert(size > 0);
    assert(alignment > 0);

    /* Next address is address + size, verify it follows alignment, if the entire 'next'
     * region doesn't fit in our MemoryBlock then return null, otherwise the address*/
    uint64_t Next = address + size;
    assert(Next > address && "Check block boundary alignment next");
    assert(Next + size > Next && "Check for wrap-around");
    assert(Next % alignment == 0);
    if (!inRange(Next, size))
        function_fail("Address not in range after alignment");

    return Next;
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::getAlignedNearestDown(const uint64_t address, const size_t alignment, const size_t size) const {
    assert(size > 0);
    assert(alignment > 0);

    auto NearestDown = reinterpret_cast<uint64_t>(PLH::AlignDownwards((char*)address, alignment));
    if (!inRange(NearestDown, size))
        function_fail("Address not in range after alignment");

    assert(NearestDown <= address && "Check block boundary alignment down");
    assert(NearestDown % alignment == 0);
    return NearestDown;
}

//[Start, End)
PLH::Maybe<uint64_t>
PLH::MemoryBlock::getAlignedNearestUp(const uint64_t address, const size_t alignment, const size_t size) const {
    assert(size > 0);
    assert(alignment > 0);

    auto NearestUp = reinterpret_cast<uint64_t>(PLH::AlignUpwards((char*)address, alignment));
    if (!inRange(NearestUp, size))
        function_fail("Address not in range after alignment");

    assert(NearestUp >= address && "Check block boundary alignment up");
    assert(NearestUp % alignment == 0);
    return NearestUp;
}

//[Start,End]
bool PLH::MemoryBlock::containsBlock(const PLH::MemoryBlock& other) const {
    return other.getStart() >= this->getStart() && other.getEnd() <= this->getEnd();
}

//[Start,End)
bool PLH::MemoryBlock::containsAddress(const uint64_t Address) const {
    return this->getStart() <= Address && Address < this->getEnd();
}

bool PLH::MemoryBlock::operator==(const PLH::MemoryBlock& other) const {
    return this->getStart() == other.getStart() &&
            this->getEnd() == other.getEnd();
}

bool PLH::MemoryBlock::operator!=(const PLH::MemoryBlock& other) const {
    return !(*this == other);
}

bool PLH::MemoryBlock::operator>(const PLH::MemoryBlock& other) const {
    //end is exclusive so others end can == others' start
    return this->getStart() >= other.getEnd();
}

bool PLH::MemoryBlock::operator<(const PLH::MemoryBlock& other) const {
    //end is exclusive so our end can == other's start
    return this->getEnd() <= other.getStart();
}

bool PLH::MemoryBlock::operator<=(const PLH::MemoryBlock& other) const {
    return *this < other || *this == other;
}

bool PLH::MemoryBlock::operator>=(const PLH::MemoryBlock& other) const {
    return *this > other || *this == other;
}

