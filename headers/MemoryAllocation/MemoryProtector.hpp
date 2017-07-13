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
    MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot) {
        m_Address = address;
        m_Length  = length;

        m_origProtection = archImp.Protect(address, length, TranslateProtection(prot));
    }

    PLH::Maybe<PLH::ProtFlag> originalProt()
    {
        return m_origProtection;
    }

    ~MemoryProtector() {
        if(!m_origProtection || m_origProtection.unwrap() == PLH::ProtFlag::UNSET)
            return;

        archImp.Protect(m_Address, m_Length, TranslateProtection(m_origProtection.unwrap()));
    }

private:
    Architecture archImp;

    PLH::Maybe<PLH::ProtFlag> m_origProtection;

    uint64_t m_Address;
    uint64_t m_Length;
};

}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP
