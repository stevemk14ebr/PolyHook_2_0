//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "headers/Enums.hpp"
#define WIN32_LEAN_AND_MEAN

#define NOMINMAX

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

#include <iostream>

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
std::ostream& operator<<(std::ostream& os, const PLH::ProtFlag v);

namespace PLH {
int TranslateProtection(const PLH::ProtFlag flags);
ProtFlag TranslateProtection(const int prot);

class MemoryProtector {
public:
	MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot, bool unsetOnDestroy = true);
	~MemoryProtector();
	PLH::ProtFlag originalProt();
	bool isGood();

private:
	PLH::ProtFlag protect(const uint64_t address, const uint64_t length, int prot);

	PLH::ProtFlag m_origProtection = PLH::ProtFlag::NONE;
	uint64_t m_address;
	uint64_t m_length;
	bool m_status;
	bool m_unsetLater;
};
}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP
