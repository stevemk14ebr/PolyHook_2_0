//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_MEMORYPAGE_HPP
#define POLYHOOK_2_0_MEMORYPAGE_HPP

#include "headers/Misc.hpp"
#include "headers/Enums.hpp"
#include "headers/UID.hpp"
#include "headers/Maybe.hpp"
#include <sstream>

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
    MemoryBlock(const uint64_t start, const uint64_t End, const PLH::ProtFlag Prot);

    MemoryBlock();

    uint64_t getStart() const;

    uint64_t getEnd() const;

    uint64_t getSize() const;

    PLH::ProtFlag getProtection() const;

    UID id() const {
        return m_uid;
    }

    /**Alignment helpers that always return in range [Start, End) of MemoryBlock. Return Value is the
     * aligned address, Alignment is desired alignment, Size is the size of the region attempting
     * to be aligned. For example if we want to find the nearest memory page to an address with an alignment
     * of 4 bytes, and we also what to ensure the aligned page address is > Address:
     * GetAlignedNearestUp(Address, 4, 4096) where 4096 is the size of a single page.**/
    PLH::Maybe<uint64_t> getAlignedFirst(const size_t alignment, const size_t size) const;

    PLH::Maybe<uint64_t> getAlignedNext(const uint64_t address, const size_t alignment, const size_t size) const;

    PLH::Maybe<uint64_t>
    getAlignedNearestUp(const uint64_t address, const size_t alignment, const size_t size) const;

    PLH::Maybe<uint64_t>
    getAlignedNearestDown(const uint64_t address, const size_t alignment, const size_t size) const;

    bool containsBlock(const PLH::MemoryBlock& other) const;

    bool containsAddress(const uint64_t address) const;

    bool operator==(const PLH::MemoryBlock& other) const;

    bool operator!=(const PLH::MemoryBlock& other) const;

    bool operator<(const PLH::MemoryBlock& other) const;

    bool operator>(const PLH::MemoryBlock& other) const;

    bool operator<=(const PLH::MemoryBlock& other) const;

    bool operator>=(const PLH::MemoryBlock& other) const;

private:
    bool inRange(const uint64_t address, const size_t size) const;

    uint64_t      m_start;
    uint64_t      m_end;
    PLH::ProtFlag m_protection;
    UID           m_uid; //makes debugging easier
};

inline std::ostream& operator<<(std::ostream& os, const PLH::MemoryBlock& obj) {
    os << std::hex << "[" << obj.getStart() << "-" << obj.getEnd() << ")" << std::dec
       << PLH::ProtFlagToString(obj.getProtection());
    return os;
}
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
