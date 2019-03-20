#include "headers/MemProtector.hpp"
#include "headers/Enums.hpp"

#define WIN32_LEAN_AND_MEAN
#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/mman.h>
#define PAGE_EXECUTE PROT_EXEC
#define PAGE_READONLY PROT_READ
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#endif

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<PLH::ProtFlag>(
		static_cast<std::uint8_t>(lhs) |
		static_cast<std::uint8_t>(rhs));
}

bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<std::uint8_t>(lhs) &
		static_cast<std::uint8_t>(rhs);
}

std::ostream& operator<<(std::ostream& os, const PLH::ProtFlag flags) {
	if (flags & PLH::ProtFlag::X)
		os << "x";
	else
		os << "-";

	if (flags & PLH::ProtFlag::R)
		os << "r";
	else
		os << "-";

	if (flags & PLH::ProtFlag::W)
		os << "w";
	else
		os << "-";

	if (flags & PLH::ProtFlag::NONE)
		os << "n";
	else
		os << "-";
	return os;
}

PLH::MemoryProtector::MemoryProtector(const uint64_t address, const uint64_t length, const PLH::ProtFlag prot,
									  bool unsetOnDestroy /*= true */)
: m_origProtection(protect(address, length, TranslateProtection(prot)))
, m_address(address)
, m_length(length)
, m_unsetLater(unsetOnDestroy)

{
}

PLH::ProtFlag PLH::MemoryProtector::originalProt() {
	return m_origProtection;
}

bool PLH::MemoryProtector::isGood() {
	return m_status;
}

PLH::MemoryProtector::~MemoryProtector() {
	if (!m_unsetLater || !isGood())
		return;
	
	protect(m_address, m_length, TranslateProtection(m_origProtection));
}


#ifdef _WIN32

PLH::ProtFlag PLH::MemoryProtector::protect(const uint64_t address, const uint64_t length, int prot) {
	DWORD orig;
	DWORD dwProt = prot;
	m_status = VirtualProtect((char*)address, (SIZE_T)length, dwProt, &orig) != 0;
	return TranslateProtection(orig);
}

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = 0;
	if (flags == PLH::ProtFlag::X)
		NativeFlag = PAGE_EXECUTE;

	if (flags == PLH::ProtFlag::R)
		NativeFlag = PAGE_READONLY;

	if (flags == PLH::ProtFlag::W || (flags == (PLH::ProtFlag::R | PLH::ProtFlag::W)))
		NativeFlag = PAGE_READWRITE;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::R))
		NativeFlag = PAGE_EXECUTE_READ;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_READWRITE;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::R) && (flags & PLH::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_READWRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PAGE_NOACCESS;
	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::NONE;
	switch (prot) {
		case PAGE_EXECUTE:
			flags = flags | PLH::ProtFlag::X;
			break;
		case PAGE_READONLY:
			flags = flags | PLH::ProtFlag::R;
			break;
		case PAGE_READWRITE:
			flags = flags | PLH::ProtFlag::W;
			flags = flags | PLH::ProtFlag::R;
			break;
		case PAGE_EXECUTE_READWRITE:
			flags = flags | PLH::ProtFlag::X;
			flags = flags | PLH::ProtFlag::R;
			flags = flags | PLH::ProtFlag::W;
			break;
		case PAGE_EXECUTE_READ:
			flags = flags | PLH::ProtFlag::X;
			flags = flags | PLH::ProtFlag::R;
			break;
		case PAGE_NOACCESS:
			flags = flags | PLH::ProtFlag::NONE;
			break;
	}
	return flags;
}
#elif __APPLE__

PLH::ProtFlag PLH::MemoryProtector::protect(const uint64_t address, const uint64_t length, int prot) {
	kern_return_t kr;
	mach_port_t object;
	vm_size_t vmsize;
	mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
	vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
	vm_region_basic_info_data_64_t info;
	long pagesize = sysconf(_SC_PAGESIZE);
	vm_address_t addr = address;
	
	kr = vm_region_64(mach_task_self(), &addr, &vmsize, flavor, (vm_region_info_t)&info, &info_count, &object);
	if (kr) {
		perror("vm_region_64");
	}
 
	auto alignedAddress = (void *)((long)address & ~(pagesize - 1));
	m_status = mprotect((void*)alignedAddress, (size_t)pagesize, prot) == 0;

	if (!m_status) {
		printf("mprotect failed:  %s\n", strerror(errno));
	}
	
	return TranslateProtection(info.protection);
}

int PLH::TranslateProtection(const PLH::ProtFlag flags)
{
	return static_cast<int>(flags);
}

PLH::ProtFlag PLH::TranslateProtection(const int prot)
{
	return static_cast<PLH::ProtFlag>(prot);
}
#endif
