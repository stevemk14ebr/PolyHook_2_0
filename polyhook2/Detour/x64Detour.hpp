//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X64DETOUR_HPP
#define POLYHOOK_2_X64DETOUR_HPP

#include <functional>
#include <optional>
using namespace std::placeholders;

#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Instruction.hpp"
#include "polyhook2/ADisassembler.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/RangeAllocator.hpp"

namespace PLH {

class x64Detour : public Detour {
public:
    enum class detour_scheme_t {
        CODE_CAVE = 1, //searching for code-cave to keep fnCallback.
        INPLACE = 2,    //use push-ret for fnCallback in-place storage.
		VALLOC2 = 3, // use virtualalloc2 to allocate in range. Only on win10 > 1803
		VALLOC2_FALLBACK_CODE_CAVE = 4, // first try to allocate, then fallback to code cave if not supported (will not fallback on failure of allocation)
    };

	x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);
	virtual ~x64Detour() override;
	virtual bool hook() override;
	virtual bool unHook() override;

	Mode getArchType() const override;

	uint8_t getMinJmpSize() const;

	uint8_t getPrefJmpSize() const;

	detour_scheme_t getDetourScheme() const;
	void setDetourScheme(detour_scheme_t scheme);

private:
	bool makeTrampoline(insts_t& prologue, insts_t& trampolineOut);

	// assumes we are looking within a +-2GB window
	template<uint16_t SIZE>
	std::optional<uint64_t> findNearestCodeCave(uint64_t addr);

	detour_scheme_t _detourScheme { detour_scheme_t::VALLOC2_FALLBACK_CODE_CAVE }; // this is the most stable configuration.
	std::optional<uint64_t> m_valloc2_region;
	RangeAllocator m_allocator;
};
}
#endif //POLYHOOK_2_X64DETOUR_HPP
