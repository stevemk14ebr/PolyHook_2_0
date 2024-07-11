#pragma once

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/Instruction.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/MemProtector.hpp"

using namespace std::placeholders;

namespace PLH {

class x86HotpatchDetour : public Detour {
public:
    x86HotpatchDetour(uint64_t fnAddress, uint64_t fnCallback, uint64_t* userTrampVar);

    virtual ~x86HotpatchDetour() = default;

    virtual bool hook() override;

    virtual bool unHook() override;

    virtual bool reHook() override;

    Mode getArchType() const override;

    uint8_t getJmpSize() const;

    uint8_t getShortJmpSize() const;

protected:

    uint64_t m_addressInAlignArea;   // 5 byte jmp location

    insts_t m_originalInstsOnFnAddress; // will be overwritten by 2 byte short jump
    insts_t m_hookInstsOnFnAddress;
    uint32_t m_hookSizeOnFnAddress;
    uint16_t m_nopProlOffsetOnFnAddress;
    uint16_t m_nopSizeOnFnAddress;

    bool makeTrampoline(insts_t& prologue, insts_t& trampolineOut);
};

}
