#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/MemProtector.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

#if defined(POLYHOOK2_OS_WINDOWS)

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

size_t PLH::MemAccessor::page_size()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	return static_cast<size_t>(sysInfo.dwPageSize);
}

#elif defined(POLYHOOK2_OS_LINUX)

bool PLH::MemAccessor::mem_copy(uint64_t dest, uint64_t src, uint64_t size) const {
	memcpy((char*)dest, (char*)src, (SIZE_T)size);
	return true;
}

bool PLH::MemAccessor::safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept {
	bool res = memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		written = size;
	else
		written = 0;

	return res;
}

bool PLH::MemAccessor::safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept {
	bool res = memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		read = size;
	else
		read = 0;

	return res;
}

PLH::ProtFlag PLH::MemAccessor::mem_protect(uint64_t dest, uint64_t size, PLH::ProtFlag prot, bool& status) const {
	status = mprotect(MEMORY_ROUND(addr, page_size()), MEMORY_ROUND_UP(size, page_size()), TranslateProtection(prot)) == 0;
	return PLH::ProtFlag::R | PLH::ProtFlag::X;
}

size_t PLH::MemAccessor::page_size()
{
	return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}

#elif defined(POLYHOOK2_OS_APPLE)

bool PLH::MemAccessor::mem_copy(uint64_t dest, uint64_t src, uint64_t size) const {
	memcpy((char*)dest, (char*)src, (SIZE_T)size);
	return true;
}

bool PLH::MemAccessor::safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept {
	bool res = memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		written = size;
	else
		written = 0;

	return res;
}

bool PLH::MemAccessor::safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept {
	bool res = memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		read = size;
	else
		read = 0;

	return res;
}

PLH::ProtFlag PLH::MemAccessor::mem_protect(uint64_t dest, uint64_t size, PLH::ProtFlag prot, bool& status) const {
	status = mach_vm_protect(mach_task_self(), (mach_vm_address_t)MEMORY_ROUND(dest, page_size()), MEMORY_ROUND_UP(size, page_size()), FALSE, TranslateProtection(prot)) == KERN_SUCCESS;
	return PLH::ProtFlag::R | PLH::ProtFlag::X;
}

size_t PLH::MemAccessor::page_size()
{
	return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}

#endif