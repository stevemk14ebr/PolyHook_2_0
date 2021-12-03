#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

uint64_t PLH::findPattern(const uint64_t rangeStart, size_t len, const char* pattern)
{
	const size_t patSize = (size_t)getPatternSize(pattern);
	auto patt_base = (char*)PolyHook2Alloca(patSize + 1);
	auto msk_base = (char*)PolyHook2Alloca(patSize + 1);
	char* pat = patt_base;
	char* msk = msk_base;

	if (patSize + 1 > len)
		return NULL;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = 0; n < (len - (patSize + 1)); ++n)
	{
		if (isMatch((char*)(rangeStart + n), patt_base, msk_base)) {
			return rangeStart + n;
		}
	}
	return NULL;
}

uint64_t PLH::getPatternSize(const char* pattern)
{
	const size_t l = strlen(pattern);

	// c = 2 * b + (b - 1) . 2 chars per byte + b - 1 spaces between
	return (l + 1) / 3;
}

uint64_t PLH::findPattern_rev(const uint64_t rangeStart, size_t len, const char* pattern)
{
	const size_t patSize = (size_t)getPatternSize(pattern);
	auto patt_base = (char*)PolyHook2Alloca(patSize + 1);
	auto msk_base = (char*)PolyHook2Alloca(patSize + 1);
	char* pat = patt_base;
	char* msk = msk_base;
	
	if (patSize + 1 > len)
		return NULL;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = len - (patSize + 1); n > 0; n--)
	{
		if (isMatch((char*)(rangeStart + n), patt_base, msk_base)) {
			return rangeStart + n;
		}
	}
	return NULL;
}

uint64_t PLH::calc_2gb_below(uint64_t address)
{
	return (address > (uint64_t)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

uint64_t PLH::calc_2gb_above(uint64_t address)
{
	return (address < (uint64_t)0xffffffff80000000) ? address + 0x7ff80000 : (uint64_t)0xfffffffffff80000;
}

#if defined(POLYHOOK2_OS_WINDOWS)

bool PLH::boundedAllocSupported()
{
	auto hMod = LoadLibraryA("kernelbase.dll");
	if(hMod == 0)
		return false;

	return GetProcAddress(hMod, "VirtualAlloc2") != 0;
}

uint64_t PLH::boundAlloc(uint64_t min, uint64_t max, uint64_t size)
{
	MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
	MEM_EXTENDED_PARAMETER param = { 0 };

	addressReqs.Alignment = 0; // any alignment
	addressReqs.LowestStartingAddress = (PVOID)min; // PAGE_SIZE aligned
	addressReqs.HighestEndingAddress = (PVOID)(max - 1); // PAGE_SIZE aligned, exclusive so -1

	param.Type = MemExtendedParameterAddressRequirements;
	param.Pointer = &addressReqs;

	auto hMod = LoadLibraryA("kernelbase.dll");
	if(hMod == 0)
		return false;

	auto pVirtualAlloc2 = (decltype(&::VirtualAlloc2))GetProcAddress(hMod, "VirtualAlloc2");
	return (uint64_t)pVirtualAlloc2(
		GetCurrentProcess(), (PVOID)0,
		(SIZE_T)size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE,
		&param, 1);
}

uint64_t PLH::boundAllocLegacy(uint64_t start, uint64_t end, uint64_t size)
{
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(si));
	GetSystemInfo(&si);

	// start low, go up
	MEMORY_BASIC_INFORMATION mbi;
	for (uint64_t Addr = (uint64_t)start; Addr < end;) {
		if (!VirtualQuery((char*)Addr, &mbi, sizeof(mbi)))
			return 0;

		assert(mbi.RegionSize != 0);
		if (mbi.State != MEM_FREE || mbi.RegionSize < size)
			continue;

		uint64_t nextPage = (uint64_t)AlignUpwards((uint64_t)mbi.BaseAddress, si.dwAllocationGranularity);
		
		if (uint64_t Allocated = (uint64_t)VirtualAlloc((char*)nextPage, (SIZE_T)size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
			return Allocated;
		} else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED) {
			Addr += size;
		} else {
			Addr = nextPage + mbi.RegionSize;
		}
	}
	return 0;
}

void PLH::boundAllocFree(uint64_t address, uint64_t size)
{
	(void)size;
	VirtualFree((LPVOID)address, (SIZE_T)0, MEM_RELEASE);
}

uint64_t PLH::getAllocationAlignment()
{
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(si));
	GetSystemInfo(&si);
	return si.dwAllocationGranularity;
}

uint64_t PLH::getPageSize()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	return static_cast<uint64_t>(sysInfo.dwPageSize);
}

#elif defined(POLYHOOK2_OS_LINUX)

bool PLH::boundedAllocSupported()
{
	return true;
}

uint64_t PLH::boundAlloc(uint64_t min, uint64_t max, uint64_t size)
{
	return boundAllocLegacy(min, max, size);
}

uint64_t PLH::boundAllocLegacy(uint64_t start, uint64_t end, uint64_t size)
{
	void* hint = (void*)((end - 1) / 2 + start / 2);
	uint64_t res = (uint64_t)mmap(hint, (size_t)size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (res == (uint64_t)MAP_FAILED)
		return 0;

	if (res < start || res >= end)
	{
		boundAllocFree(res, size);
		return 0;
	}

	return res;
}

void PLH::boundAllocFree(uint64_t address, uint64_t size)
{
	munmap((void*)address, (size_t)size);
}

uint64_t PLH::getAllocationAlignment()
{
/*
From malloc-internal.h and malloc-alignment.h

#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif
// The corresponding word size. 
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
                          ? __alignof__ (long double) : 2 * SIZE_SZ)
*/
	//return (2 * sizeof(size_t) < __alignof__ (long double) ? __alignof__ (long double) : 2 * sizeof(size_t));

	return getPageSize();
}

uint64_t PLH::getPageSize()
{
	return static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
}

#elif defined(POLYHOOK2_OS_APPLE)

bool PLH::boundedAllocSupported()
{
	return false;
}

uint64_t PLH::boundAlloc(uint64_t min, uint64_t max, uint64_t size)
{
	return boundAllocLegacy(min, max, size);
}

uint64_t PLH::boundAllocLegacy(uint64_t start, uint64_t end, uint64_t size)
{
	// VM_FLAGS_ANYWHERE allows for better compatibility as the Kernel will find a place for us.
	//int flags = (address_hint == nullptr ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED);
	int flags = VM_FLAGS_FIXED;

	uint64_t increment = getAllocationAlignment();
	for (uint64_t address = start; address < (end - 1); address += increment)
	{
		void* res = (void*)address;
		if (mach_vm_allocate(task, &res, (mach_vm_size_t)size, flags) == KERN_SUCCESS)
		{
			address = (uint64_t)res;
			if (address >= start && address < end)
				return address;

			boundAllocFree(address, size);
		}
	}
	
	return 0;
}

void PLH::boundAllocFree(uint64_t address, uint64_t size)
{
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, size);
}

uint64_t PLH::getAllocationAlignment()
{
	return PLH::MemAccessor::getPageSize();
}

uint64_t PLH::getPageSize()
{
	return static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
}

#endif
