//
// Created by steve on 7/5/17.
//
#include "polyhook2/Detour/x64Detour.hpp"

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

std::optional<uint64_t> PLH::x64Detour::findNearestCodeCave(uint64_t addr, uint8_t minSz) {
	HANDLE hSelf = GetCurrentProcess();
	unsigned char* data = new unsigned char[64000];
	memset(data, 0, 64000);

	// RPM so we don't pagefault, careful to check for partial reads

	// Search Above
	SIZE_T read = 0;
	if (ReadProcessMemory(hSelf, (char*)addr, data, 64000, &read) || GetLastError() == ERROR_PARTIAL_COPY) {
		uint32_t contiguous = 0;
		for (uint32_t i = 0; i < read; i++) {
			if (data[i] == 0xCC) {
				contiguous++;
			} else {
				contiguous = 0;
			}

			if (contiguous >= minSz) {
				delete[] data;
				return addr + i - contiguous + 1;
			}
		}
	}

	//memset(data, 0, 64000);
	//read = 0;
	//if (ReadProcessMemory(hSelf, (char*)(addr - 64000), data, 64000, &read) || GetLastError() == ERROR_PARTIAL_COPY) {
	//	uint32_t contiguous = 0;
	//	for (uint32_t i = 0; i < read; i++) {
	//		if (data[i] == 0xCC) {
	//			contiguous++;
	//		} else {
	//			contiguous = 0;
	//		}

	//		if (contiguous >= minSz) {
	//			delete[] data;
	//			return addr - 64000 + i - contiguous;
	//		}
	//	}
	//}

	delete[] data;
	return {};
}

bool PLH::x64Detour::hook() {
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
	if (insts.empty()) {
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

	uint64_t minProlSz = getPrefJmpSize(); // min size of patches that may split instructions
	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	std::optional<PLH::insts_t> prologueOpt;
	bool useMinJmp = false;
	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
		if (!prologueOpt) {
		trysmall:
			// try the smaller 6 byte jmp
			if (roundProlSz >= getMinJmpSize()) {
				minProlSz = getMinJmpSize();
				roundProlSz = minProlSz;
				prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
			}

			if (prologueOpt) {
				useMinJmp = true;
			} else {
				ErrorLog::singleton().push("Function too small to hook safely!", ErrorLevel::SEV);
				return false;
			}
		}

		assert(roundProlSz >= minProlSz);
		prologue = *prologueOpt;

		if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
			//ErrorLog::singleton().push("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
			//return false;
			goto trysmall;
		}
	}

	m_originalInsts = prologue;
	ErrorLog::singleton().push("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);
	
	{   // copy all the prologue stuff to trampoline
		insts_t jmpTblOpt;
		if (!makeTrampoline(prologue, jmpTblOpt)) {
			if (useMinJmp) {
				return false;
			} else {
				goto trysmall;
			}
		}

		ErrorLog::singleton().push("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz)) + "\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			ErrorLog::singleton().push("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;

	MemoryProtector prot(m_fnAddress, roundProlSz, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	if (useMinJmp) {
		// we're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
		auto cave = findNearestCodeCave(m_fnAddress, 8);
		if (!cave) {
			ErrorLog::singleton().push("Function too small to hook safely, no code caves found near function", ErrorLevel::SEV);
			return false;
		}

		const auto prolJmp = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
		m_disasm.writeEncoding(prolJmp);
	} else {
		const auto prolJmp = makex64PreferredJump(m_fnAddress, m_fnCallback);
		m_disasm.writeEncoding(prolJmp);
	}
	
	// Nop the space between jmp and end of prologue
	assert(roundProlSz >= minProlSz);
	const uint8_t nopSz = (uint8_t)(roundProlSz - minProlSz);
	std::memset((char*)(m_fnAddress + minProlSz), 0x90, (size_t)nopSz);

	m_hooked = true;
	return true;
}

bool PLH::x64Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
	assert(!prologue.empty());
	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);
	const uint8_t destHldrSz = 8;

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works
	
	The relocation could also because of data operations too. But that's specific to the function and can't
	work again on a retry (same function, duh). Return immediately in that case.**/
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
		m_trampolineSz = (uint16_t)(prolSz + (getMinJmpSize() + destHldrSz) +
			(getMinJmpSize() + destHldrSz)* neededEntryCount);
		m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

		const int64_t delta = m_trampoline - prolStart;

		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc))
			return false;
	} while (instsNeedingEntry.size() > neededEntryCount);

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	const uint64_t jmpHolderCurAddr = m_trampoline + m_trampolineSz - destHldrSz;
	{
		const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);

		ErrorLog::singleton().push("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
		m_disasm.writeEncoding(jmpToProl);
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