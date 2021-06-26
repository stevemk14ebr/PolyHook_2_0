
#ifndef POLYHOOK_2_MEMORYACCESSOR_HPP
#define POLYHOOK_2_MEMORYACCESSOR_HPP
#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/Enums.hpp"

#define MEMORY_ROUND(_numToRound_, _multiple_) \
    (_numToRound_ & (((size_t)-1) ^ (_multiple_ - 1)))

// Round _numToRound_ to the next higher _multiple_
#define MEMORY_ROUND_UP(_numToRound_, _multiple_) \
    ((_numToRound_ + (_multiple_ - 1)) & (((size_t)-1) ^ (_multiple_ - 1)))

namespace PLH {
	/**
	Overriding these routines can allow cross-process/cross-arch hooks
	**/
	class MemAccessor {
	public:
		virtual ~MemAccessor() = default;

		/**
		Defines a memory read/write routine that may fail ungracefully. It's expected
		this library will only ever use this routine in cases that are expected to succeed.
		**/
		virtual bool mem_copy(uint64_t dest, uint64_t src, uint64_t size) const;

		/**
		Defines a memory write routine that will not throw exceptions, and can handle potential
		writes to NO_ACCESS or otherwise innaccessible memory pages. Defaults to writeprocessmemory.
		Must fail gracefully
		**/
		virtual bool safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept;

		/**
		Defines a memory read routine that will not throw exceptions, and can handle potential
		reads from NO_ACCESS or otherwise innaccessible memory pages. Defaults to readprocessmemory.
		Must fail gracefully
		**/
		virtual bool safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept;
	
		virtual PLH::ProtFlag mem_protect(uint64_t dest, uint64_t size, PLH::ProtFlag newProtection, bool& status) const;
	};
}
#endif
