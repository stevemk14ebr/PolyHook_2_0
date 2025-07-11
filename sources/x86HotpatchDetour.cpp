#include "polyhook2/Detour/x86HotpatchDetour.hpp"

#include <cassert>

namespace PLH {

	x86HotpatchDetour::x86HotpatchDetour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar)
    : Detour(fnAddress, fnCallback, userTrampVar, getArchType()) {}

Mode x86HotpatchDetour::getArchType() const {
    return Mode::x86;
}

uint8_t x86HotpatchDetour::getJmpSize() const {
    return 5;
}

uint8_t x86HotpatchDetour::getShortJmpSize() const {
    return 2;
}

bool x86HotpatchDetour::hook() {
    Log::log("x86 hotpatch detour is assuming the very beginning of a function is passed in", ErrorLevel::WARN);
    Log::log("m_fnAddress: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);
	
    insts_t orig_insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress+100, *this);

    Log::log("passed in original function:\n" + instsToStr(orig_insts) + "\n", ErrorLevel::INFO);
    if (orig_insts.empty()) {
        Log::log("Disassembler unable to decode any valid instructions at m_fnAddress", ErrorLevel::SEV);
        return false;
    }

    if (!followJmp(orig_insts)) {
        Log::log("Prologue jmp resolution at m_fnAddress failed", ErrorLevel::SEV);
        return false;
    }

    // new m_fnAddress
    m_fnAddress = orig_insts.front().getAddress();
    Log::log("original function after jump resolution:\n" + instsToStr(orig_insts) + "\n", ErrorLevel::INFO);

    int orig_insts_bytes_len = calcInstsSz(orig_insts);

    Log::log("try to disassemble backwards until we find the previous function end point:\n", ErrorLevel::INFO);
    insts_t backward_insts = m_disasm.disassemble_backward_until_prev_func_end(m_fnAddress, *this);
    Log::log("backward until prev function end:\n" + instsToStr(backward_insts) + "\n", ErrorLevel::INFO);
    if (backward_insts.empty()) {
        Log::log("Disassembler unable to decode any valid instructions before fnAddress", ErrorLevel::SEV);
        return false;
    }
    int backward_inst_bytes_len = 0;
    // asserting this area is full of no-op instructions
    for(const auto& ins : backward_insts)
    {
	    if (!ins.getIsNoOp())
	    {
            {
                std::stringstream ss;
                ss << ins;
                Log::log("Please determine if '" + ss.str() + "' is a no-op, report to us please", ErrorLevel::SEV);
                return false;
            }
	    }
        backward_inst_bytes_len += ins.getBytes().size();
    }

    // check whether we can put short jump in this function
    if (orig_insts_bytes_len < getShortJmpSize())
    {
        Log::log("Original function is too narrow to put short jump", ErrorLevel::SEV);
        return false;
    }
    if (backward_inst_bytes_len < getJmpSize())
    {
        Log::log("backward until prev function end is too narrow to put x86 5-byte jump", ErrorLevel::SEV);
        return false;
    }

    if (!followJmp(backward_insts)) {
        Log::log("Prologue jmp resolution at backward_insts failed", ErrorLevel::SEV);
        return false;
    }
	//                        hook point             saved_original_instructions  hook_instructions
    // 2 bytes short jump -> m_fnAddress             m_originalInstsOnFnAddress  m_hookInstsOnFnAddress  this part is specific to hotpatch
    // 5 bytes long jump  -> m_addressInAlignArea    m_originalInsts             m_hookInsts             this part using x86Detour logic
    // m_fnAddress, m_originalInsts and m_hookInsts are not representing the same memory block, we should override all hooking methods

    // set align area address
    m_addressInAlignArea = backward_insts.front().getAddress();
    Log::log("m_addressInAlignArea: " + int_to_hex(m_addressInAlignArea) + "\n", ErrorLevel::INFO);
    

    // --------------- END RECURSIVE JMP RESOLUTION ---------------------
    
    uint64_t minProlSzInAlignArea = getJmpSize(); // min size of patches that may split instructions
    uint64_t roundProlSzInAlignArea = minProlSzInAlignArea; // nearest size to min that doesn't split any instructions

    uint64_t minProlSzOnFnAddress = getShortJmpSize(); // min size of patches that may split instructions
    uint64_t roundProlSzOnFnAddress = minProlSzOnFnAddress; // nearest size to min that doesn't split any instructions
    
    // find the prologue section we will overwrite with jmp + zero or more nops
    auto prologueOptInAlignArea = calcNearestSzForHotpatch(backward_insts, minProlSzInAlignArea, roundProlSzInAlignArea);
    if (!prologueOptInAlignArea) {
        Log::log("instructions in align area is too small to hook safely!", ErrorLevel::SEV);
        return false;
    }
    assert(roundProlSzInAlignArea >= minProlSzInAlignArea);
    auto prologueInAlignArea = *prologueOptInAlignArea;

    auto prologueOptOnFnAddress = calcNearestSz(orig_insts, minProlSzOnFnAddress, roundProlSzOnFnAddress);
    if (!prologueOptOnFnAddress) {
        Log::log("instructions on m_fnAddress is too small to hook safely!", ErrorLevel::SEV);
        return false;
    }

    assert(roundProlSzOnFnAddress >= minProlSzOnFnAddress);
    auto prologueOnFnAddress = *prologueOptOnFnAddress;
    
    if (!expandProlSelfJmps(prologueOnFnAddress, orig_insts, minProlSzOnFnAddress, roundProlSzOnFnAddress)) {
        Log::log("instructions on fn_Address need a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
        return false;
    }

    m_originalInstsOnFnAddress = prologueOnFnAddress;
    Log::log("Prologue on fnAddress to overwrite with 2 bytes jump:\n" + instsToStr(prologueOnFnAddress) + "\n", ErrorLevel::INFO);

    m_originalInsts = prologueInAlignArea;
    Log::log("Prologue in align area to overwrite with 5 bytes jump:\n" + instsToStr(prologueInAlignArea) + "\n", ErrorLevel::INFO);
    
    // copy all the prologue stuff to trampoline, no need to consider prologue in align area
    // asserting these instructions are no-op
    insts_t jmpTblOpt;
    if (!makeTrampoline(prologueOnFnAddress, jmpTblOpt)) {
        return false;
    }
    Log::log("m_trampoline: " + int_to_hex(m_trampoline) + "\n", ErrorLevel::INFO);
    Log::log("m_trampolineSz: " + int_to_hex(m_trampolineSz) + "\n", ErrorLevel::INFO);
    
    auto tramp_instructions = m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
    Log::log("Trampoline:\n" + instsToStr(tramp_instructions) + "\n\n", ErrorLevel::INFO);
    if (!jmpTblOpt.empty()) {
        Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n\n", ErrorLevel::INFO);
    }
    
    *m_userTrampVar = m_trampoline;
    m_hookSize = (uint32_t) roundProlSzInAlignArea;
    m_nopProlOffset = (uint16_t) minProlSzInAlignArea;
    
    MemoryProtector prot(m_addressInAlignArea, m_hookSize, ProtFlag::RWX, *this);
    m_hookInsts = makex86Jmp(m_addressInAlignArea, m_fnCallback);
    Log::log("Hook instructions in align area:\n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);
    
    // Nop the space between jmp and end of prologue
    assert(m_hookSize >= m_nopProlOffset);
    m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
    const auto nops = make_nops(m_addressInAlignArea + m_nopProlOffset, m_nopSize);
    ZydisDisassembler::writeEncoding(nops, *this);

    Log::log("Hook size in align area: " + std::to_string(m_hookSize) + "\n", ErrorLevel::INFO);
    Log::log("Prologue offset in align area: " + std::to_string(m_nopProlOffset) + "\n", ErrorLevel::INFO);

	// handle the short jump part
    m_hookSizeOnFnAddress = (uint32_t) roundProlSzOnFnAddress;
    m_nopProlOffsetOnFnAddress = (uint16_t) minProlSzOnFnAddress;

    MemoryProtector prot_shortjmp(m_fnAddress, m_hookSizeOnFnAddress, ProtFlag::RWX, *this);
    m_hookInstsOnFnAddress = makex86ShortJmp(m_fnAddress, m_addressInAlignArea);
    Log::log("Hook instructions on fn_Address:\n" + instsToStr(m_hookInstsOnFnAddress) + "\n", ErrorLevel::INFO);
    ZydisDisassembler::writeEncoding(m_hookInstsOnFnAddress, *this);

    assert(m_hookSizeOnFnAddress >= m_nopProlOffsetOnFnAddress);
    m_nopSizeOnFnAddress = (uint16_t)(m_hookSizeOnFnAddress - m_nopProlOffsetOnFnAddress);
    const auto nopsOnFnAddress = make_nops(m_fnAddress + m_nopProlOffsetOnFnAddress, m_nopSizeOnFnAddress);
    ZydisDisassembler::writeEncoding(nopsOnFnAddress, *this);

    Log::log("Hook size on fnAddress: " + std::to_string(m_hookSizeOnFnAddress) + "\n", ErrorLevel::INFO);
    Log::log("Prologue offset on fnAddress: " + std::to_string(m_nopProlOffsetOnFnAddress) + "\n", ErrorLevel::INFO);

    m_hooked = true;
    return true;
}

bool x86HotpatchDetour::unHook() {
    if (!m_hooked) {
        Log::log("x86HotpatchDetour unhook failed: no hook present", ErrorLevel::SEV);
        return false;
    }
    // restore 2 bytes short jump
    MemoryProtector prot_short(m_fnAddress, calcInstsSz(m_originalInstsOnFnAddress), ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
    ZydisDisassembler::writeEncoding(m_originalInstsOnFnAddress, *this);

    // restore 5 bytes jump
    MemoryProtector prot(m_addressInAlignArea, calcInstsSz(m_originalInsts), ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
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

bool x86HotpatchDetour::reHook() {
    MemoryProtector prot(m_addressInAlignArea, m_hookSize, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_hookInsts, *this);

    // Nop the space between jmp and end of prologue
    assert(m_hookSize >= m_nopProlOffset);
    const auto nops = make_nops(m_addressInAlignArea + m_nopProlOffset, m_nopSize);
    ZydisDisassembler::writeEncoding(nops, *this);

    // handle the short jump part

    MemoryProtector prot_shortjmp(m_fnAddress, m_hookSizeOnFnAddress, ProtFlag::RWX, *this);
    ZydisDisassembler::writeEncoding(m_hookInstsOnFnAddress, *this);

    assert(m_hookSizeOnFnAddress >= m_nopProlOffsetOnFnAddress);
    const auto nopsOnFnAddress = make_nops(m_fnAddress + m_nopProlOffsetOnFnAddress, m_nopSizeOnFnAddress);
    ZydisDisassembler::writeEncoding(nopsOnFnAddress, *this);

    return true;
}

bool x86HotpatchDetour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
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
            neededEntryCount = (uint8_t)instsNeedingEntry.size();
        }

        // prol + jmp back to prol + N * jmpEntries
        m_trampolineSz = (uint16_t)(prolSz + getJmpSize() + getJmpSize() * neededEntryCount);
        m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

        const int64_t delta = m_trampoline - prolStart;

        buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
    } while (instsNeedingEntry.size() > neededEntryCount);

    const int64_t delta = m_trampoline - prolStart;
    MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

    // Insert jmp from trampoline -> prologue after overwritten section
    const uint64_t jmpToProlAddr = m_trampoline + prolSz;
    const auto jmpToProl = makex86Jmp(jmpToProlAddr, prolStart + prolSz);
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
