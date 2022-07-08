#include "polyhook2/Detour/ADetour.hpp"

#include <cmath>

namespace PLH {

uint8_t Detour::getMaxDepth() const {
    return m_maxDepth;
}

void Detour::setMaxDepth(uint8_t maxDepth) {
    assert(maxDepth > 0 && "Max depth must be positive");
    m_maxDepth = maxDepth;
}

std::optional<insts_t> Detour::calcNearestSz(
    const insts_t& functionInsts,
    const uint64_t prolOvrwStartOffset,
    uint64_t& prolOvrwEndOffset
) {
    uint64_t prolLen = 0;
    insts_t instructionsInRange;

    // count instructions until at least length needed or func end
    bool endHit = false;
    for (const auto& inst: functionInsts) {
        prolLen += inst.size();
        instructionsInRange.push_back(inst);

        // only safe to overwrite pad bytes once end is hit
        if (endHit && !ZydisDisassembler::isPadBytes(inst))
            break;

        if (ZydisDisassembler::isFuncEnd(inst))
            endHit = true;

        if (prolLen >= prolOvrwStartOffset)
            break;
    }

    prolOvrwEndOffset = prolLen;
    if (prolLen >= prolOvrwStartOffset) {
        return instructionsInRange;
    }

    return std::nullopt;
}

bool Detour::followJmp(insts_t& functionInsts, const uint8_t curDepth) { // NOLINT(misc-no-recursion)
    if (functionInsts.empty()) {
        Log::log("Couldn't decompile instructions at followed jmp", ErrorLevel::WARN);
        return false;
    }

    if (curDepth >= m_maxDepth) {
        Log::log("Prologue jmp resolution hit max depth, prologue too deep", ErrorLevel::WARN);
        return false;
    }

    // not a branching instruction, no resolution needed
    if (!functionInsts.front().isBranching()) {
        return true;
    }

    // might be a mem type like jmp rax, not supported
    if (!functionInsts.front().hasDisplacement()) {
        Log::log("Branching instruction without displacement encountered", ErrorLevel::WARN);
        return false;
    }

    uint64_t dest = functionInsts.front().getDestination();
    functionInsts = m_disasm.disassemble(dest, dest, dest + 100, *this);
    return followJmp(functionInsts, curDepth + 1); // recurse
}

bool Detour::expandProlSelfJmps(insts_t& prol, const insts_t& func, uint64_t& minProlSz, uint64_t& roundProlSz) {
    uint64_t maxAddr = 0;
    const uint64_t prolStart = prol.front().getAddress();
    const branch_map_t& branchMap = m_disasm.getBranchMap();
    for (size_t i = 0; i < prol.size(); i++) {
        auto inst = prol.at(i);

        // is there a jump pointing at the current instruction?
        if (branchMap.find(inst.getAddress()) == branchMap.end())
            continue;

        insts_t srcs = branchMap.at(inst.getAddress());
        for (const auto& src: srcs) {
            const uint64_t srcEndAddr = src.getAddress() + src.size();
            if (srcEndAddr > maxAddr)
                maxAddr = srcEndAddr;
        }

        minProlSz = maxAddr - prolStart;

        // expand prol by one entry size, may fail if prol too small
        const auto prolOpt = calcNearestSz(func, minProlSz, roundProlSz);
        if (!prolOpt) {
            return false;
        }
        prol = *prolOpt; // False flag: LocalValueEscapesScope
    }

    return true;
}

void Detour::buildRelocationList(
    insts_t& prologue,
    const uint64_t roundProlSz,
    const int64_t delta,
    insts_t& instsNeedingEntry,
    insts_t& instsNeedingReloc,
    insts_t& instsNeedingTranslation
) {
    assert(instsNeedingEntry.empty());
    assert(instsNeedingReloc.empty());
    assert(!prologue.empty());

    const uint64_t prolStart = prologue.front().getAddress();

    for (auto& inst: prologue) {
        if (!inst.hasDisplacement()) {
            continue; // Skip instructions that don't have relative displacement
        }
        const auto dispSzBits = (uint8_t) inst.getDispSize() * 8;
        // 2^(bitSz-1) give max val, and -1 because signed ex (int8_t [-128, 127] = [-2^7, 2^7 - 1]
        const auto maxInstDisp = (uint64_t) (std::pow(2, dispSzBits - 1) - 1.0);
        const auto absDelta = (uint64_t) std::llabs(delta);

        // types that change control flow
        if (inst.isBranching() &&
            (inst.getDestination() < prolStart ||
             inst.getDestination() > prolStart + roundProlSz)) {

            //indirect-call always needs an entry (only a dest-holder)
            //its destination cannot be used for relocating since it is already dereferenced.(ref: inst.getDestination)
            if (inst.isCalling() && inst.isIndirect()) {
                instsNeedingEntry.push_back(inst);
            } else {
                // can inst just be re-encoded or do we need a tbl entry
                if (absDelta > maxInstDisp) {
                    instsNeedingEntry.push_back(inst);
                } else {
                    instsNeedingReloc.push_back(inst);
                }
            }
        }

        // data operations (duplicated because clearer)
        if (!inst.isBranching()) { // Can this happen on 32-bit?
            if (absDelta > maxInstDisp) {
                /*
                 * EX: 48 8d 0d 96 79 07 00    lea rcx, [rip + 0x77996]
                 * If instruction is moved beyond displacement field width
                 * we can't fix the displacement. Hence, we add it to the list of
                 * instructions that need to be translated to equivalent ones.
                 */
                instsNeedingTranslation.push_back(inst);
            } else {
                instsNeedingReloc.push_back(inst);
            }
        }
    }
}

bool Detour::unHook() {
    if (!m_hooked) {
        Log::log("Detour unhook failed: no hook present", ErrorLevel::SEV);
        return false;
    }

    MemoryProtector prot(m_fnAddress, calcInstsSz(m_originalInsts), ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
    ZydisDisassembler::writeEncoding(m_originalInsts, *this);

    if (m_trampoline != NULL) {
        delete[](uint8_t*) m_trampoline;
        m_trampoline = NULL;
    }

    if (m_userTrampVar != nullptr) {
        *m_userTrampVar = NULL;
	}

    m_hooked = false;
    return true;
}

bool Detour::reHook() {
    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);

    // Nop the space between jmp and end of prologue
    if (m_hookSize < m_nopProlOffset) {
        Log::log("hook size must not be larger than nop prologue offset", ErrorLevel::SEV);
        return false;
    }

    const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
    ZydisDisassembler::writeEncoding(nops, *this);

    return true;
}

insts_t Detour::make_nops(uint64_t address, uint16_t size) const {
    if (size < 1) {
        return {};
    }

    static const uint8_t max_nop_size = 9;

    const auto make_nop_inst = [&](const std::vector<uint8_t>& bytes) {
        return Instruction(address, {0}, 0, false, false, bytes, "nop", "", getArchType());
    };

    // lambda updates the address for each created instruction
    const auto make_nop = [&](const uint8_t nop_size) {
        assert(nop_size <= max_nop_size);

        // https://stackoverflow.com/questions/25545470/long-multi-byte-nops-commonly-understood-macros-or-other-notation
        switch (nop_size) {
            case 1: return make_nop_inst({0x90});
            case 2: return make_nop_inst({0x66, 0x90});
            case 3: return make_nop_inst({0x0F, 0x1F, 0x00});
            case 4: return make_nop_inst({0x0F, 0x1F, 0x40, 0x00});
            case 5: return make_nop_inst({0x0F, 0x1F, 0x44, 0x00, 0x00});
            case 6: return make_nop_inst({0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00});
            case 7: return make_nop_inst({0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00});
            case 8: return make_nop_inst({0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
            default:return make_nop_inst({0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
        }
    };

    insts_t nops;

    auto max_nop_count = (int) (size / max_nop_size);
    auto remainder_nop_size = (uint8_t) (size % max_nop_size);

    for (int i = 0; i < max_nop_count; i++) {
        nops.emplace_back(make_nop(max_nop_size));
        address += max_nop_size;
    }

    if (remainder_nop_size) {
        nops.emplace_back(make_nop(remainder_nop_size));
    }

    return nops;
}

}
