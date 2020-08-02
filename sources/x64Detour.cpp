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
	const uint64_t chunkSize = 64000;
	unsigned char* data = new unsigned char[chunkSize];

	// RPM so we don't pagefault, careful to check for partial reads
	auto calc_2gb_below = [](uint64_t address) -> uint64_t
	{
		return (address > (uint64_t)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
	};

	auto calc2gb_above = [](uint64_t address) -> uint64_t
	{
		return (address < (uint64_t)0xffffffff80000000) ? address + 0x7ff80000 : (uint64_t)0xfffffffffff80000;
	};
	
	// Search 2GB below
	for (uint64_t search = addr - chunkSize; (search + chunkSize) >= calc_2gb_below(addr); search -= chunkSize) {
		memset(data, 0, chunkSize);

		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			uint32_t contiguousInt3 = 0;
			uint32_t contiguousNop = 0;
			assert(read <= chunkSize);
			if (read == 0)
				continue;

			// read from highest address first (closest to prologue)
			for (size_t i = read - 1; i > 0; i--) {
				assert(i >= 0);
				if (data[i] == 0xCC) {
					contiguousInt3++;
				} else {
					contiguousInt3 = 0;
				}

				if (data[i] == 0x90) {
					contiguousNop++;
				} else {
					contiguousNop = 0;
				}

				if (contiguousInt3 >= minSz || contiguousNop >= minSz) {
					delete[] data;
					return search + i;
				}
			}
		}
	}

	// Search 2GB above
	for (uint64_t search = addr; (search + chunkSize) < calc2gb_above(addr); search += chunkSize) {
		memset(data, 0, chunkSize);

		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			uint32_t contiguousInt3 = 0;
			uint32_t contiguousNop = 0;

			assert(read <= chunkSize);
			for (size_t i = 0; i < read; i++) {
				if (data[i] == 0xCC) {
					contiguousInt3++;
				} else {
					contiguousInt3 = 0;
				}

				if (data[i] == 0x90) {
					contiguousNop++;
				} else {
					contiguousNop = 0;
				}

				if (contiguousInt3 >= minSz || contiguousNop >= minSz) {
					delete[] data;
					return search + i - contiguousInt3 + 1;
				}
			}
		}
	}

	delete[] data;
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

	MemoryProtector prot(m_fnAddress, roundProlSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	// we're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
	auto cave = findNearestCodeCave(m_fnAddress, 8);
	if (!cave) {
		Log::log("Function too small to hook safely, no code caves found near function", ErrorLevel::SEV);
		return false;
	}

	MemoryProtector holderProt(*cave, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
	const auto prolJmp = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
	m_disasm.writeEncoding(prolJmp, *this);

	// Nop the space between jmp and end of prologue
	assert(roundProlSz >= minProlSz);
	const uint8_t nopSz = (uint8_t)(roundProlSz - minProlSz);
	writeNop(m_fnAddress + minProlSz, nopSz);

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
			Log::log("Failed to calculate trampoline information", ErrorLevel::SEV);
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
