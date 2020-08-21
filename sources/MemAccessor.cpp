#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/MemProtector.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

bool PLH::MemAccessor::mem_copy(uint64_t dest, uint64_t src, uint64_t size) const {
	memcpy((char*)dest, (char*)src, (SIZE_T)size);
	return true;
}

bool PLH::MemAccessor::safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept {
	written = 0;
	return WriteProcessMemory(GetCurrentProcess(), (char*)dest, (char*)src, (SIZE_T)size, (PSIZE_T)&written);
}

bool PLH::MemAccessor::safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept {
	read = 0;
	return ReadProcessMemory(GetCurrentProcess(), (char*)src, (char*)dest, (SIZE_T)size, (PSIZE_T)&read) || (GetLastError() == ERROR_PARTIAL_COPY);
}

PLH::ProtFlag PLH::MemAccessor::mem_protect(uint64_t dest, uint64_t size, PLH::ProtFlag prot, bool& status) const {
	DWORD orig;
	status = VirtualProtect((char*)dest, (SIZE_T)size, TranslateProtection(prot), &orig) != 0;
	return TranslateProtection(orig);
}