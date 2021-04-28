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

namespace PLH {

class x64Detour : public Detour {
public:
    enum class detour_scheme_t {
        CODE_CAVE = 1, //searching for code-cave to keep fnCallback.
        INPLACE = 2    //use push-ret for fnCallback in-place storage.
    };

	x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);

	x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis);
	virtual ~x64Detour() = default;
	virtual bool hook() override;

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

	detour_scheme_t _detourScheme { detour_scheme_t::CODE_CAVE }; //default CODE_CAVE for backward compatiblity
};
}
#endif //POLYHOOK_2_X64DETOUR_HPP
