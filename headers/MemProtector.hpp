//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "headers/Enums.hpp"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs);

namespace PLH {
	std::string ProtFlagToString(PLH::ProtFlag flags);
	int	TranslateProtection(const PLH::ProtFlag flags);
	ProtFlag TranslateProtection(const int prot);

	class MemoryProtector
	{
	public:
		MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot) {
			m_address = address;
			m_length = length;

			m_origProtection = PLH::ProtFlag::UNSET;
			m_origProtection = protect(address, length, TranslateProtection(prot));
		}

		PLH::ProtFlag originalProt() {
			return m_origProtection;
		}

		~MemoryProtector() {
			if(m_origProtection == PLH::ProtFlag::UNSET)
				return;

			protect(m_address, m_length, TranslateProtection(m_origProtection));
		}
	private:
		PLH::ProtFlag protect(const uint64_t address, const uint64_t length, int prot) {
			DWORD orig = 0;
			VirtualProtect((char*)address, length, prot, &orig);
			return TranslateProtection(orig);
		}

		PLH::ProtFlag m_origProtection;

		uint64_t m_address;
		uint64_t m_length;
	};
}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP