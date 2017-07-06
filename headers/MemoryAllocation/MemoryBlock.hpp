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
    PLH::Maybe<uint64_t> GetAlignedFirst(const size_t Alignment, const size_t Size) const;

    PLH::Maybe<uint64_t> GetAlignedNext(const uint64_t Address, const size_t Alignment, const size_t Size) const;

    PLH::Maybe<uint64_t>
    GetAlignedNearestUp(const uint64_t Address, const size_t Alignment, const size_t Size) const;

    PLH::Maybe<uint64_t>
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

inline std::ostream& operator<<(std::ostream& os, const PLH::MemoryBlock& obj) {
    os << std::hex << "[" << obj.GetStart() << "-" << obj.GetEnd() << ")" << std::dec
       << PLH::ProtFlagToString(obj.GetProtection());
    return os;
}
}
#endif //POLYHOOK_2_0_MEMORYPAGE_HPP
