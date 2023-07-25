//
// Created by steve on 7/5/17.
//
#include "polyhook2/Detour/x86Detour.hpp"

namespace PLH {

x86Detour::x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar)
    : Detour(fnAddress, fnCallback, userTrampVar, getArchType()) {}

Mode x86Detour::getArchType() const {
    return Mode::x86;
}

uint8_t getJmpSize() {
    return 5;
}

bool x86Detour::hook() {
    Log::log("m_fnAddress: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);
	
    insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
    Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);
	
    if (insts.empty()) {
        Log::log("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
        return false;
    }

    if (!followJmp(insts)) {
        Log::log("Prologue jmp resolution failed", ErrorLevel::SEV);
        return false;
    }

    // update given fn address to resolved one
    m_fnAddress = insts.front().getAddress();

    // --------------- END RECURSIVE JMP RESOLUTION ---------------------

    uint64_t minProlSz = getJmpSize(); // min size of patches that may split instructions
    uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

    // find the prologue section we will overwrite with jmp + zero or more nops
    auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
    if (!prologueOpt) {
        Log::log("Function too small to hook safely!", ErrorLevel::SEV);
        return false;
    }

    assert(roundProlSz >= minProlSz);
    auto prologue = *prologueOpt;

    if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
        Log::log("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
        return false;
    }

    m_originalInsts = prologue;
    Log::log("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

    // copy all the prologue stuff to trampoline
    insts_t jmpTblOpt;
    if (!makeTrampoline(prologue, jmpTblOpt)) {
        return false;
    }

    auto tramp_instructions = m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
    Log::log("Trampoline:\n" + instsToStr(tramp_instructions) + "\n\n", ErrorLevel::INFO);
    if (!jmpTblOpt.empty()) {
        Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n\n", ErrorLevel::INFO);
    }

    *m_userTrampVar = m_trampoline;
    m_hookSize = (uint32_t) roundProlSz;
    m_nopProlOffset = (uint16_t) minProlSz;

    MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);

    m_hookInsts = makex86Jmp(m_fnAddress, m_fnCallback);
    Log::log("Hook instructions:\n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);

    // Nop the space between jmp and end of prologue
    assert(m_hookSize >= m_nopProlOffset);
    m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
    const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
    ZydisDisassembler::writeEncoding(nops, *this);

    m_hooked = true;
    return true;
}

bool x86Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
    assert(!prologue.empty());
    const uint64_t prolStart = prologue.front().getAddress();
    const uint16_t prolSz = calcInstsSz(prologue);

    /** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
    address will change each attempt, which changes delta, which changes the number of needed entries. So
    we just try until we hit that lucky number that works.

    The relocation could also because of data operations too. But that's specific to the function and can't
    work again on a retry (same function, duh). Return immediately in that case.
    **/
    uint8_t neededEntryCount = 5;
    insts_t instsNeedingEntry;
    insts_t instsNeedingReloc;
    insts_t instsNeedingTranslation;

    uint8_t retries = 0;
    do {
        if (retries++ > 4) {
            Log::log("Failed to calculate trampoline information", ErrorLevel::SEV);
            return false;
        }

        if (m_trampoline != NULL) {
            delete[](unsigned char*) m_trampoline;
            neededEntryCount = (uint8_t) instsNeedingEntry.size();
        }

        // prol + jmp back to prol + N * jmpEntries
        m_trampolineSz = (uint16_t) (prolSz + getJmpSize() + getJmpSize() * neededEntryCount);
        m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

        const int64_t delta = m_trampoline - prolStart;

        buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
    } while (instsNeedingEntry.size() > neededEntryCount);

    const int64_t delta = m_trampoline - prolStart;
    MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

    // Insert jmp from trampoline -> prologue after overwritten section
    const uint64_t jmpToProlAddr = m_trampoline + prolSz;
    const auto jmpToProl = makex86Jmp(jmpToProlAddr, prologue.front().getAddress() + prolSz);
    ZydisDisassembler::writeEncoding(jmpToProl, *this);

    const auto makeJmpFn = [=](uint64_t a, Instruction& inst) mutable {
        // move inst to trampoline and point instruction to entry
        auto oldDest = inst.getDestination();
        inst.setAddress(inst.getAddress() + delta);
        inst.setDestination(a);

        return makex86Jmp(a, oldDest);
    };

    const uint64_t jmpTblStart = jmpToProlAddr + getJmpSize();
    trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);
    return true;
}

}
