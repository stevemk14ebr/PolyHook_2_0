#ifndef POLYHOOK_2_PAGEALLOCATOR_HPP
#define POLYHOOK_2_PAGEALLOCATOR_HPP

#include "polyhook2/Misc.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cassert>
#include <limits>
#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace PLH {

	/** Given some starting address and some excusive range allocate and return memory 
	pages within that section in linearly increasing order, with each new block being contiguously
	allocated from the next free spot. Blocks are requested by variable size, and pages are allocated
	within the allowed range to back these if needed. A page will be split if blocks smaller than page size
	are requested. Blocks however will never be split across a page. Blocks cannot be freed once requested, 
	you must destroy the entire allocator which will free all backing pages, and thus all blocks, 
	this is cuz im lazy, i accept pr's :)**/
	struct SplitPage {
		// start address of page
		uint64_t address;

		// offset into page pointing at first unused byte
		uint64_t unusedOffset;

		uint64_t getUnusedAddr() const {
			return address + unusedOffset;
		}
	};

	class PageAllocator {
	public:
		/** Construct an allocator to return pages within [address, address + size).
		If size is zero, then it will try to allocate anywhere**/
		PageAllocator(const uint64_t address, const uint64_t size);
		~PageAllocator();

		uint64_t getBlock(const uint64_t size);
	private:
		const uint64_t WIN_PAGE_SZ = 0x1000;

		uint64_t m_regionStart;
		uint64_t m_regionSize;

		// vector of pages + unused cursor
		static std::vector<SplitPage> m_pages;
		static std::recursive_mutex m_pageMtx;
		static std::atomic<uint8_t> m_refCount;
	};

	inline uint64_t AllocateWithinRange(uint64_t pStart, int64_t Delta);
}

inline uint64_t PLH::AllocateWithinRange(const uint64_t pStart, const int64_t Delta) {
	/**
	If WIN >= 2004 this can be simplified by using:
	MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
	MEM_EXTENDED_PARAMETER extendedParams = { 0 };
	extendedParams.Type = MemExtendedParameterAddressRequirements;
	extendedParams.Pointer = &addressReqs;

	addressReqs.LowestStartingAddress =
	addressReqs.HighestEndingAddress =

	VirtualAlloc2(GetCurrentProcess(), NULL, m_trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, &extendedParams, 1);
	**/

	/*These lambda's let us use a single for loop for both the forward and backward loop conditions.
	I passed delta variable as a parameter instead of capturing it because it is faster, it allows
	the compiler to optimize the lambda into a function pointer rather than constructing
	an anonymous class and incur the extra overhead that involves (negligible overhead but why not optimize)*/
	auto Incrementor = [](int64_t Delta, MEMORY_BASIC_INFORMATION& mbi) -> uint64_t {
		if (Delta > 0)
			return (uint64_t)mbi.BaseAddress + mbi.RegionSize;
		else
			return (uint64_t)mbi.BaseAddress - 1; //TO-DO can likely jump much more than 1 byte, figure out what the max is
	};

	auto Comparator = [](int64_t Delta, uint64_t Addr, uint64_t End)->bool {
		if (Delta > 0)
			return Addr < End;
		else
			return Addr > End;
	};

	SYSTEM_INFO si;
	memset(&si, 0, sizeof(si));
	GetSystemInfo(&si);

	//Start at pStart, search around it (up/down depending on Delta)
	MEMORY_BASIC_INFORMATION mbi;
	for (uint64_t Addr = (uint64_t)pStart; Comparator(Delta, Addr, (uint64_t)pStart + Delta); Addr = Incrementor(Delta, mbi))
	{
		if (!VirtualQuery((char*)Addr, &mbi, sizeof(mbi)))
			return 0;

		assert(mbi.RegionSize != 0);

		// TODO: Fails on PAGE_NO_ACCESS type for now
		if (mbi.State != MEM_FREE)
			continue;
		
		// address online alignment boundary, split it (upwards)
		if ((uint64_t)mbi.BaseAddress & (si.dwAllocationGranularity - 1)) {
			uint64_t nextPage = (uint64_t)PLH::AlignUpwards((char*)mbi.BaseAddress, si.dwAllocationGranularity);
			uint64_t unusableSize = nextPage - (uint64_t)mbi.BaseAddress;
			Addr = nextPage;

			if (uint64_t Allocated = (uint64_t)VirtualAlloc((char*)nextPage, (SIZE_T)(mbi.RegionSize - unusableSize), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
				return Allocated;
		} else {
			//VirtualAlloc requires 64k aligned addresses
			assert((uint64_t)mbi.BaseAddress % si.dwAllocationGranularity == 0);
			if (uint64_t Allocated = (uint64_t)VirtualAlloc((char*)mbi.BaseAddress, (SIZE_T)si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
				return Allocated;
		}
	}
	return 0;
}
#endif
