#include "polyhook2/RangeAllocator.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <algorithm>

PLH::FBAllocator::FBAllocator(uint64_t min, uint64_t max, uint8_t blockSize, uint8_t blockCount) : m_allocator(nullptr), m_hAllocator(0) {
	m_min = min;
	m_max = max;
	m_dataPool = 0;
	m_maxBlocks = blockCount;
	m_usedBlocks = 0;
	m_blockSize = blockSize;
	m_alloc2Supported = boundedAllocSupported();
}

PLH::FBAllocator::~FBAllocator()
{
	if (m_allocator) {
		delete m_allocator;
		m_allocator = 0;
		m_hAllocator = 0;
	}

	if(m_dataPool) { 
		VirtualFree((PVOID)m_dataPool, 0, MEM_RELEASE);
		m_dataPool = 0;
	}
}

bool PLH::FBAllocator::initialize()
{
	uint64_t alignment = getAllocationAlignment();
	uint64_t start = (uint64_t)AlignUpwards(m_min, (size_t)alignment);
	uint64_t end = (uint64_t)AlignDownwards(m_max, (size_t)alignment);
	
	if (m_alloc2Supported) {
		// alignment shrinks area by aligning both towards middle so we don't allocate beyond the given bounds
		m_dataPool = boundAlloc(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * (uint64_t)m_maxBlocks);
		if (!m_dataPool) {
			return false;
		}
	} else {
		m_dataPool = boundAllocLegacy(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * (uint64_t)m_maxBlocks);
		if (!m_dataPool) {
			return false;
		}
	}
	
    m_allocator = new ALLOC_Allocator{ "PLH", (char*)m_dataPool, 
		m_blockSize, ALLOC_BLOCK_SIZE(m_blockSize), m_maxBlocks, NULL, 0, 0, 0, 0, 0};
	if (!m_allocator) {
		return false;
	}

    m_hAllocator = m_allocator;
	return true;
}

char* PLH::FBAllocator::allocate()
{
	if (m_usedBlocks + 1 == m_maxBlocks) {
		return 0;
	}
	m_usedBlocks++;
	return (char*)ALLOC_Alloc(m_hAllocator, m_blockSize);
}

char* PLH::FBAllocator::callocate(uint8_t num)
{
	m_usedBlocks += num;
	return (char*)ALLOC_Calloc(m_hAllocator, num, m_blockSize);
}

void PLH::FBAllocator::deallocate(char* mem)
{
	m_usedBlocks--;
	ALLOC_Free(m_hAllocator, mem);
}

bool PLH::FBAllocator::inRange(uint64_t addr)
{
	if (addr >= m_min && addr < m_max) {
		return true;
	}
	return false;
}

bool PLH::FBAllocator::intersectsRange(uint64_t min, uint64_t max)
{
	uint64_t _min = std::max(m_min, min);
	uint64_t _max = std::min(m_max, max);
	if (_min <= _max)
		return true;
	return false;
}

uint8_t PLH::FBAllocator::intersectionLoadFactor(uint64_t min, uint64_t max)
{
	assert(intersectsRange(min, max));
	uint64_t _min = std::max(m_min, min);
	uint64_t _max = std::min(m_max, max);
	double intersectLength = (double)(_max - _min);
	return (uint8_t)((intersectLength / (max - min)) * 100.0);
}

PLH::RangeAllocator::RangeAllocator(uint8_t blockSize, uint8_t blockCount)
{
	m_maxBlocks = blockCount;
	m_blockSize = blockSize;
}

std::shared_ptr<PLH::FBAllocator> PLH::RangeAllocator::findOrInsertAllocator(uint64_t min, uint64_t max)
{
	for (auto& allocator : m_allocators) {
		if (allocator->inRange(min) && allocator->inRange(max - 1)) {
			return allocator;
		}
	}

	auto allocator = std::make_shared<FBAllocator>(min, max, m_blockSize, m_maxBlocks);
	if (!allocator->initialize())
		return nullptr;

	m_allocators.push_back(allocator);
	return allocator;
}

char* PLH::RangeAllocator::allocate(uint64_t min, uint64_t max)
{
	static bool is32 = sizeof(void*) == 4;
	if (is32 && max > 0x7FFFFFFF) {
		max = 0x7FFFFFFF; // allocator apis fail in 32bit above this range
	}

	std::lock_guard<std::mutex> m_lock(m_mutex);
	auto allocator = findOrInsertAllocator(min, max);
	if (!allocator) {
		return nullptr;
	}

	char* addr = allocator->allocate();
	m_allocMap[(uint64_t)addr] = allocator;
	return addr;
}

void PLH::RangeAllocator::deallocate(uint64_t addr)
{
	std::lock_guard<std::mutex> m_lock(m_mutex);
	if (auto it{ m_allocMap.find(addr) }; it != std::end(m_allocMap)) {
		auto allocator = it->second;
		allocator->deallocate((char*)addr);
		m_allocMap.erase(addr);

		// this instance + instance in m_allocators array
		if (allocator.use_count() == 2) {
			m_allocators.erase(std::remove(m_allocators.begin(), m_allocators.end(), allocator), m_allocators.end());
		}
	} else {
		assert(false);
	}
}