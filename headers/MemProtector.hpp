//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "headers/Enums.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <iostream>

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
std::ostream& operator<<(std::ostream& os, const PLH::ProtFlag v);

namespace PLH {
int	TranslateProtection(const PLH::ProtFlag flags);
ProtFlag TranslateProtection(const int prot);

class MemoryProtector {
public:
	MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot, bool unsetOnDestroy = true) {
		m_address = address;
		m_length = length;
		unsetLater = unsetOnDestroy;

		m_origProtection = PLH::ProtFlag::UNSET;
		m_origProtection = protect(address, length, TranslateProtection(prot));
	}

	PLH::ProtFlag originalProt() {
		return m_origProtection;
	}

	bool isGood() {
		return status;
	}

	~MemoryProtector() {
		if (m_origProtection == PLH::ProtFlag::UNSET || !unsetLater)
			return;

		protect(m_address, m_length, TranslateProtection(m_origProtection));
	}
private:
	PLH::ProtFlag protect(const uint64_t address, const uint64_t length, int prot) {
		DWORD orig;
		DWORD dwProt = prot;
		status = VirtualProtect((char*)address, (SIZE_T)length, dwProt, &orig) != 0;
		return TranslateProtection(orig);
	}

	PLH::ProtFlag m_origProtection;

	uint64_t m_address;
	uint64_t m_length;
	bool status;
	bool unsetLater;
};
}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP