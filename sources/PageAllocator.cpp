#include "headers/PageAllocator.hpp"

std::vector<PLH::SplitPage> PLH::PageAllocator::m_pages;
std::recursive_mutex PLH::PageAllocator::m_pageMtx;
std::atomic<uint8_t> PLH::PageAllocator::m_refCount = 0;

PLH::PageAllocator::PageAllocator(const uint64_t address, const uint64_t size) : m_regionStart(address), m_regionSize(size) {
	m_refCount++;
}

PLH::PageAllocator::~PageAllocator() {
	// future me may hate myself for locking in destructor
	std::lock_guard<std::recursive_mutex> lock(m_pageMtx);

	if (m_refCount.fetch_sub(1) == 1) {
		for (const SplitPage& page : m_pages) {
			VirtualFree((char*)page.address, (SIZE_T)WIN_PAGE_SZ, MEM_RELEASE);
		}
		m_pages.clear();
	}
}

uint64_t PLH::PageAllocator::getBlock(const uint64_t size) {

	std::lock_guard<std::recursive_mutex> lock(m_pageMtx);

	// Search available pages first
	for (SplitPage& page : m_pages) {
		const uint64_t unusedPtr = (uint64_t)PLH::AlignUpwards((char*)page.getUnusedAddr(), 64);
		const uint64_t proposedEnd = unusedPtr + size;
		const uint64_t pageEnd = page.address + WIN_PAGE_SZ;
		if (m_regionStart <= unusedPtr && proposedEnd <= pageEnd) {
			// size + alignment unusable space
			page.unusedOffset += size + (unusedPtr - page.getUnusedAddr());
			return unusedPtr;
		}
	}
	
	uint64_t searchSz = m_regionSize ? m_regionSize : std::numeric_limits<int64_t>::max();
	uint64_t Allocated = AllocateWithinRange(m_regionStart, searchSz);
	if (Allocated == 0)
		return 0;

	SplitPage page;
	page.address = Allocated;
	page.unusedOffset = 0;
	m_pages.push_back(std::move(page));

	return getBlock(size);
}

