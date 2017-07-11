//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "headers/Maybe.hpp"
#include "headers/Enums.hpp"
#include "headers/MemoryAllocation/UnixImpl/UnixMemProtImp.hpp"

#include <cstdint>

namespace PLH {

template<typename Architecture>
class MemoryProtector
{
public:
    MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot) :
            originalProtection(archImp.Protect(address, length, TranslateProtection(prot))) {
        m_Address = address;
        m_Length  = length;
    }

    PLH::Maybe<PLH::ProtFlag> origProtection() {
        if (originalProtection)
            return originalProtection.unwrap();
        function_fail(originalProtection.unwrapError());
    }

    ~MemoryProtector() {
        if (originalProtection && originalProtection != PLH::ProtFlag::UNSET)
            archImp.Protect(m_Address, m_Length, TranslateProtection(originalProtection.unwrap()));
    }

private:
    Architecture archImp;

    PLH::Maybe<PLH::ProtFlag> originalProtection;
    uint64_t                  m_Address;
    uint64_t                  m_Length;
};

}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP
