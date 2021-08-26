#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

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

#elif defined(POLYHOOK2_OS_LINUX)

struct region_t {
	uint64_t start;
	uint64_t end;
	PLH::ProtFlag prot;
};

static region_t get_region_from_addr(uint64_t addr) {
	region_t res{};

	std::ifstream f("/proc/self/maps");
	std::string s;
	while (std::getline(f, s)) {
		if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos)
		{
			char* strend = &s[0];
			uint64_t start = strtoul(strend  , &strend, 16);
			uint64_t end   = strtoul(strend+1, &strend, 16);
			if (start != 0 && end != 0 && start <= addr && addr < end) {
				res.start = start;
				res.end = end;

				++strend;
				if (strend[0] == 'r')
					res.prot = res.prot | PLH::ProtFlag::R;
	
				if (strend[1] == 'w')
					res.prot = res.prot | PLH::ProtFlag::W;
	
				if (strend[2] == 'x')
					res.prot = res.prot | PLH::ProtFlag::X;

				if(res.prot == PLH::ProtFlag::UNSET)
					res.prot = PLH::ProtFlag::NONE;

				break;
			}
		}
	}
	return res;
}

bool PLH::MemAccessor::mem_copy(uint64_t dest, uint64_t src, uint64_t size) const {
	memcpy((char*)dest, (char*)src, (size_t)size);
	return true;
}

bool PLH::MemAccessor::safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept {
	region_t region_infos = get_region_from_addr(src);
	
	// Make sure that the region we query is writable
	if(!(region_infos.prot & PLH::ProtFlag::W))
		return false;
	
	size = std::min<uint64_t>(region_infos.end - src, size);
	
	memcpy((void*)dest, (void*)src, (size_t)size);
	written = size;

	return true;
}

bool PLH::MemAccessor::safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept {
	region_t region_infos = get_region_from_addr(src);
	
	// Make sure that the region we query is readable
	if(!(region_infos.prot & PLH::ProtFlag::R))
		return false;

	size = std::min<uint64_t>(region_infos.end - src, size);

	memcpy((void*)dest, (void*)src, (size_t)size);
	read = size;

	return true;
}

PLH::ProtFlag PLH::MemAccessor::mem_protect(uint64_t dest, uint64_t size, PLH::ProtFlag prot, bool& status) const {
	region_t region_infos = get_region_from_addr(dest);
	uint64_t aligned_dest = MEMORY_ROUND(dest, PLH::getPageSize());
	uint64_t aligned_size = MEMORY_ROUND_UP(size, PLH::getPageSize());
	status = mprotect((void*)aligned_dest, aligned_size, TranslateProtection(prot)) == 0;
	return region_infos.prot;
}

#elif defined(POLYHOOK2_OS_APPLE)

bool PLH::MemAccessor::mem_copy(uint64_t dest, uint64_t src, uint64_t size) const {
	memcpy((char*)dest, (char*)src, (size_t)size);
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
	status = mach_vm_protect(mach_task_self(), (mach_vm_address_t)MEMORY_ROUND(dest, PLH::getPageSize()), (mach_vm_size_t)MEMORY_ROUND_UP(size, PLH::getPageSize()), FALSE, TranslateProtection(prot)) == KERN_SUCCESS;
	return PLH::ProtFlag::R | PLH::ProtFlag::X;
}

#endif
