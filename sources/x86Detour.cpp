//
// Created by steve on 7/5/17.
//
#include "polyhook2/Detour/x86Detour.hpp"

PLH::x86Detour::x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::x86Detour::x86Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::Mode PLH::x86Detour::getArchType() const {
	return PLH::Mode::x86;
}

uint8_t PLH::x86Detour::getJmpSize() const {
	return 5;
}

bool PLH::x86Detour::hook() {
	// ------- Must resolve callback first, so that m_disasm branchmap is filled for prologue stuff
	insts_t callbackInsts = m_disasm.disassemble(m_fnCallback, m_fnCallback, m_fnCallback + 100);
	if (callbackInsts.empty()) {
		ErrorLog::singleton().push("Disassembler unable to decode any valid callback instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followJmp(callbackInsts)) {
		ErrorLog::singleton().push("Callback jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn callback address to resolved one
	m_fnCallback = callbackInsts.front().getAddress();

	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100);
	if (insts.size() <= 0) {
		ErrorLog::singleton().push("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followJmp(insts)) {
		ErrorLog::singleton().push("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn address to resolved one
	m_fnAddress = insts.front().getAddress();

	// --------------- END RECURSIVE JMP RESOLUTION ---------------------

	ErrorLog::singleton().push("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

	uint64_t minProlSz = getJmpSize(); // min size of patches that may split instructions
	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
		if (!prologueOpt) {
			ErrorLog::singleton().push("Function too small to hook safely!", ErrorLevel::SEV);
			return false;
		}

		assert(roundProlSz >= minProlSz);
		prologue = *prologueOpt;

		if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
			ErrorLog::singleton().push("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
			return false;
		}
	}

	m_originalInsts = prologue;
	ErrorLog::singleton().push("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

	{   // copy all the prologue stuff to trampoline
		insts_t jmpTblOpt;
		if (!makeTrampoline(prologue, jmpTblOpt))
			return false;

		ErrorLog::singleton().push("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz)) + "\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			ErrorLog::singleton().push("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;

	MemoryProtector prot(m_fnAddress, roundProlSz, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	const auto prolJmp = makex86Jmp(m_fnAddress, m_fnCallback);
	m_disasm.writeEncoding(prolJmp);

	// Nop the space between jmp and end of prologue
	assert(roundProlSz >= minProlSz);
	const uint8_t nopSz = (uint8_t)(roundProlSz - minProlSz);
	std::memset((char*)(m_fnAddress + minProlSz), 0x90, (size_t)nopSz);

	m_hooked = true;
	return true;
}

bool PLH::x86Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
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
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;

	uint8_t retries = 0;
	do {
		if (retries++ > 4) {
			ErrorLog::singleton().push("Failed to calculate trampoline information", ErrorLevel::SEV);
			return false;
		}

		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
			neededEntryCount = (uint8_t)instsNeedingEntry.size();
		}

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(prolSz + getJmpSize() + getJmpSize() * neededEntryCount);
		m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

		const int64_t delta = m_trampoline - prolStart;

		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc))
			return false;
	} while (instsNeedingEntry.size() > neededEntryCount);

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	{
		const auto jmpToProl = makex86Jmp(jmpToProlAddr, prologue.front().getAddress() + prolSz);
		m_disasm.writeEncoding(jmpToProl);
	}

	const uint64_t jmpTblStart = jmpToProlAddr + getJmpSize();
	trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, getJmpSize(), makex86Jmp, instsNeedingReloc, instsNeedingEntry);
	return true;
}