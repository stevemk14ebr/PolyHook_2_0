//
// Created by steve on 7/5/17.
//
#include <sstream>
#include <algorithm>
#include <functional>

#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/MemProtector.hpp"

PLH::x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::x64Detour::x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::Mode PLH::x64Detour::getArchType() const {
	return PLH::Mode::x64;
}

uint8_t PLH::x64Detour::getMinJmpSize() const {
	return 6;
}

uint8_t PLH::x64Detour::getPrefJmpSize() const {
	return 16;
}

template<uint16_t SIZE>
std::optional<uint64_t> PLH::x64Detour::findNearestCodeCave(uint64_t addr) {
	const uint64_t chunkSize = 64000;
	unsigned char* data = new unsigned char[chunkSize];
	auto delete_data = finally([=]() {
		delete[] data;
	});

	// RPM so we don't pagefault, careful to check for partial reads
	auto calc_2gb_below = [](uint64_t address) -> uint64_t
	{
		return (address > (uint64_t)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
	};

	auto calc2gb_above = [](uint64_t address) -> uint64_t
	{
		return (address < (uint64_t)0xffffffff80000000) ? address + 0x7ff80000 : (uint64_t)0xfffffffffff80000;
	};
	
	// these patterns are listed in order of most accurate to least accurate with size taken into account
	// simple c3 ret is more accurate than c2 ?? ?? and series of CC or 90 is more accurate than complex multi-byte nop
	std::string CC_PATTERN_RET = "c3 " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RET = "c3 " + repeat_n("90", SIZE, " ");

	std::string CC_PATTERN_RETN = "c2 ?? ?? " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RETN = "c2 ?? ?? " + repeat_n("90", SIZE, " ");

	const char* NOP2_RET = "c3 0f 1f 44 00 00";
	const char* NOP3_RET = "c3 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RET = "c3 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RET = "c3 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RET = "c3 cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RET = "c3 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RET = "c3 cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RET = "c3 cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	
	const char* NOP2_RETN = "c2 ?? ?? 0f 1f 44 00 00";
	const char* NOP3_RETN = "c2 ?? ?? 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RETN = "c2 ?? ?? 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RETN = "c2 ?? ?? 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RETN = "c2 ?? ?? 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

	// Scan in same order as listing above
	const char* PATTERNS_OFF1[] = {
		CC_PATTERN_RET.c_str(), NOP1_PATTERN_RET.c_str(),
		NOP2_RET, NOP3_RET, NOP4_RET, NOP5_RET,NOP6_RET,
		NOP7_RET, NOP8_RET, NOP9_RET, NOP10_RET, NOP11_RET
	};

	const char* PATTERNS_OFF3[] = {
		CC_PATTERN_RETN.c_str(), NOP1_PATTERN_RETN.c_str(),
		NOP2_RETN, NOP3_RETN, NOP4_RETN, NOP5_RETN,NOP6_RETN,
		NOP7_RETN, NOP8_RETN, NOP9_RETN, NOP10_RETN, NOP11_RETN,
	};

	// Most common:
	// https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
	// We check for rets to verify it's not like like a mid function or jmp table pad
	// [0xc3 | 0xC2 ? ? ? ? ] & 6666666666660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccccccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 660f1f840000000000

	// Search 2GB below
	for (uint64_t search = addr - chunkSize; (search + chunkSize) >= calc_2gb_below(addr); search -= chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t)findPattern_rev((uint64_t)data, read, pattern)) {
					return search + (found + offset - (uint64_t)data);
				}
				return {};
			};

			for (const char* pat : PATTERNS_OFF1) {
				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat : PATTERNS_OFF3) {
				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}

	// Search 2GB above
	for (uint64_t search = addr; (search + chunkSize) < calc2gb_above(addr); search += chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			uint32_t contiguousInt3 = 0;
			uint32_t contiguousNop = 0;

			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t)findPattern((uint64_t)data, read, pattern)) {
					return search + (found + offset - (uint64_t)data);
				}
				return {};
			};

			for (const char* pat : PATTERNS_OFF1) {
				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat : PATTERNS_OFF3) {
				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}
	return {};
}

bool PLH::x64Detour::hook() {
	// ------- Must resolve callback first, so that m_disasm branchmap is filled for prologue stuff
	insts_t callbackInsts = m_disasm.disassemble(m_fnCallback, m_fnCallback, m_fnCallback + 100, *this);
	if (callbackInsts.empty()) {
		Log::log("Disassembler unable to decode any valid callback instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followJmp(callbackInsts)) {
		Log::log("Callback jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn callback address to resolved one
	m_fnCallback = callbackInsts.front().getAddress();

	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
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
	Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

	uint64_t minProlSz = getMinJmpSize(); // min size of patches that may split instructions
	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	std::optional<PLH::insts_t> prologueOpt;
	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
		if (!prologueOpt) {
			Log::log("Function too small to hook safely!", ErrorLevel::SEV);
			return false;
		}

		assert(roundProlSz >= minProlSz);
		prologue = *prologueOpt;

		if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
			Log::log("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
			return false;
		}
	}

	m_originalInsts = prologue;
	Log::log("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);
	
	{   // copy all the prologue stuff to trampoline
		insts_t jmpTblOpt;
		if (!makeTrampoline(prologue, jmpTblOpt)) {
			return false;
		}

		Log::log("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this)) + "\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;
	m_hookSize = (uint32_t)roundProlSz;
	m_nopProlOffset = (uint16_t)minProlSz;

	MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	// we're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
	auto cave = findNearestCodeCave<8>(m_fnAddress);
	if (!cave) {
		Log::log("Function too small to hook safely, no code caves found near function", ErrorLevel::SEV);
		return false;
	}

	MemoryProtector holderProt(*cave, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
	m_disasm.writeEncoding(m_hookInsts, *this);

	// Nop the space between jmp and end of prologue
	assert(m_hookSize >= m_nopProlOffset);
	m_nopSize = (uint16_t)(m_hookSize - m_nopProlOffset);
	writeNop(m_fnAddress + m_nopProlOffset, m_nopSize);

	m_hooked = true;
	return true;
}

bool PLH::x64Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
	assert(!prologue.empty());
	assert(m_trampoline == NULL);

	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);
	const uint8_t destHldrSz = 8;

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works
	
	The relocation could also because of data operations too. But that's specific to the function and can't
	work again on a retry (same function, duh). Return immediately in that case.**/
	uint8_t neededEntryCount = 0;
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;
	uint8_t retries = 0;

	bool good = false;
	do {
		neededEntryCount = std::max((uint8_t)instsNeedingEntry.size(), (uint8_t)5);
		
		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(prolSz + (getMinJmpSize() + destHldrSz) +
			(getMinJmpSize() + destHldrSz)* neededEntryCount);

		// allocate new trampoline before deleting old to increase odds of new mem address
		uint64_t tmpTrampoline = (uint64_t)new unsigned char[m_trampolineSz];
		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
		}

		m_trampoline = tmpTrampoline;
		const int64_t delta = m_trampoline - prolStart;

		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc))
			continue;

		good = true;
	} while (retries++ < 5 && !good);

	if (!good) {
		return false;
	}

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	const uint64_t jmpHolderCurAddr = m_trampoline + m_trampolineSz - destHldrSz;
	{
		const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);

		Log::log("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
		m_disasm.writeEncoding(jmpToProl, *this);
	}

	// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
	const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, uint64_t b) mutable {
		captureAddress -= destHldrSz;
		assert(captureAddress > (uint64_t)m_trampoline && (captureAddress + destHldrSz) < (m_trampoline + m_trampolineSz));
		return makex64MinimumJump(a, b, captureAddress);
	};

	const uint64_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
	trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, getMinJmpSize(),
													makeJmpFn, instsNeedingReloc, instsNeedingEntry);

	return true;
}
