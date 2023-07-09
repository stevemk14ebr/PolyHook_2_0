//
// Created by steve on 7/4/17.
//

#ifndef POLYHOOK_2_X64DETOUR_HPP
#define POLYHOOK_2_X64DETOUR_HPP

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Instruction.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/RangeAllocator.hpp"
#include <asmjit/asmjit.h>

namespace PLH {

using std::optional;

class x64Detour : public Detour {

public:
    enum detour_scheme_t : uint8_t {
        VALLOC2 = 1 << 0, // use virtualalloc2 to allocate in range. Only on win10 > 1803
        INPLACE = 1 << 1,    // use push-ret for fnCallback in-place storage.
        CODE_CAVE = 1 << 2, //searching for code-cave to keep fnCallback.
        INPLACE_SHORT = 1 << 3, // spoils rax register
        RECOMMENDED = VALLOC2 | INPLACE | CODE_CAVE,
        // first try to allocate, then fallback to code cave if not supported.
        // will not fallback on failure of allocation
        ALL = RECOMMENDED | INPLACE_SHORT,
    };

    x64Detour(uint64_t fnAddress, uint64_t fnCallback, uint64_t* userTrampVar);

    ~x64Detour() override;

    bool hook() override;

    bool unHook() override;

    Mode getArchType() const override;

    static uint8_t getMinJmpSize();

    detour_scheme_t getDetourScheme() const;

    void setDetourScheme(detour_scheme_t scheme);

    static const char* printDetourScheme(detour_scheme_t scheme);

protected:
    detour_scheme_t m_detourScheme = detour_scheme_t::RECOMMENDED; // this is the most stable configuration.
    optional<uint64_t> m_valloc2_region;
    RangeAllocator m_allocator;
    asmjit::JitRuntime m_asmjit_rt;
    detour_scheme_t m_chosen_scheme = detour_scheme_t::VALLOC2;

    bool makeTrampoline(insts_t& prologue, insts_t& outJmpTable);

    // assumes we are looking within a +-2GB window
    template<uint16_t SIZE>
    optional<uint64_t> findNearestCodeCave(uint64_t address);

    optional<uint64_t> generateTranslationRoutine(const Instruction& instruction, uint64_t resume_address);

    bool make_inplace_trampoline(uint64_t base_address, const std::function<void(asmjit::x86::Assembler&)>& builder);

    bool allocate_jump_to_callback();
};

}
#endif //POLYHOOK_2_X64DETOUR_HPP
