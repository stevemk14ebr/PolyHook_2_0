//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x64Detour.hpp"

PLH::x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

PLH::x64Detour::x64Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

PLH::Mode PLH::x64Detour::getArchType() const {
    return PLH::Mode::x64;
}

/**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHoldershould point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.**/
PLH::insts_t PLH::x64Detour::makeMinimumJump(const uint64_t address, const uint64_t destination, const uint64_t destHolder) const {
	PLH::Instruction::Displacement disp = { 0 };
	disp.Relative = PLH::Instruction::calculateRelativeDisplacement<int32_t>(address, destHolder, 6);

	std::vector<uint8_t> bytes(6);
	bytes[0] = 0xFF;
	bytes[1] = 0x25;
	memcpy(&bytes[2], &disp.Relative, 4);

	std::stringstream ss;
	ss << std::hex << "[" << destHolder << "] ->" << destination;

	memcpy((void*)destHolder, &destination, sizeof(uint64_t));

	return { Instruction(address, disp, 2, true, bytes, "jmp", ss.str(), Mode::x64) };
}

/**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
 * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
PLH::insts_t PLH::x64Detour::makePreferredJump(const uint64_t address, const uint64_t destination) const {
	PLH::Instruction::Displacement zeroDisp = { 0 };
	uint64_t                       curInstAddress = address;

	std::stringstream ss;
	ss << std::hex << destination;

	std::vector<uint8_t> movRaxBytes;
	movRaxBytes.resize(10);
	movRaxBytes[0] = 0x48;
	movRaxBytes[1] = 0xB8;
	memcpy(&movRaxBytes[2], &destination, 8);

	auto movRax = Instruction(curInstAddress, zeroDisp, 0, false, 
								movRaxBytes, "mov", "rax, " + ss.str(), Mode::x64);
	curInstAddress += movRax.size();

	std::vector<uint8_t> xchgBytes = { 0x48, 0x87, 0x04, 0x24 };
	auto xchgRspRax = Instruction(curInstAddress, zeroDisp, 0, false, 
									xchgBytes, "xchg", "QWORD PTR [rsp],rax", Mode::x64);
	curInstAddress += xchgRspRax.size();

	std::vector<uint8_t> retBytes = { 0xC3};
	auto ret = Instruction(curInstAddress, zeroDisp, 0, false, 
							retBytes, "ret", "", Mode::x64);
	curInstAddress += ret.size();

	return { movRax, xchgRspRax, ret };
}

uint8_t PLH::x64Detour::getMinJmpSize() const {
	return 6;
}

uint8_t PLH::x64Detour::getPrefJmpSize() const {
	return 15;
}

bool PLH::x64Detour::hook() {
	// ------- Must resolve callback first, so that m_disasm branchmap is filled for prologue stuff
	insts_t callbackInsts = m_disasm.disassemble(m_fnCallback, m_fnCallback, m_fnCallback + 100);
	if (callbackInsts.size() <= 0) {
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

	std::cout << "Original function:" << std::endl << insts << std::endl;

	uint64_t minProlSz = getMinJmpSize(); // min size of patches that may split instructions
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

	//std::cout << "Prologue to overwrite:" << std::endl << prologue << std::endl;

	//{   // copy all the prologue stuff to trampoline
	//	auto makeJmpFn = std::bind(&x64Detour::makePreferredJump, this, _1, _2, _3);
	//	auto jmpTblOpt = makeTrampoline(prologue, roundProlSz, getPrefJmpSize(), makeJmpFn);

	//	std::cout << "Trampoline:" << std::endl << m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz) << std::endl;
	//	if (jmpTblOpt)
	//		std::cout << "Trampoline Jmp Tbl:" << std::endl << *jmpTblOpt << std::endl;
	//}

	//MemoryProtector prot(m_fnAddress, roundProlSz, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	//auto prolJmp = makeJmp(m_fnAddress, m_fnCallback);
	/*m_disasm.writeEncoding(prolJmp);*/

	// Nop the space between jmp and end of prologue
	const uint8_t nopSz = (uint8_t)(roundProlSz - minProlSz);
	std::memset((char*)(m_fnAddress + minProlSz), 0x90, (size_t)nopSz);

	m_hooked = true;
	return true;
}

bool PLH::x64Detour::unHook() {
	return true;
}

std::optional<PLH::insts_t> PLH::x64Detour::makeTrampoline(insts_t& prologue)
{
	assert(prologue.size() > 0);
	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);
	const uint8_t pushRaxSz = 1;
	const uint8_t destHldrSz = 8;

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works**/
	uint8_t neededEntryCount = 5;
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;
	do {
		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
			neededEntryCount = (uint8_t)instsNeedingEntry.size();
		}

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(pushRaxSz + prolSz + (getMinJmpSize() + destHldrSz) +
			(getMinJmpSize() + destHldrSz)* neededEntryCount);
		m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

		int64_t delta = m_trampoline + pushRaxSz - prolStart;

		buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc);
	} while (instsNeedingEntry.size() > neededEntryCount);

	const int64_t delta = m_trampoline + pushRaxSz - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, false);

	{
		PLH::Instruction::Displacement disp = { 0 };
		auto pushRax = Instruction(m_trampoline, disp, 0, false,
			{ 0x50 }, "push", "rax", Mode::x64);
		m_disasm.writeEncoding(pushRax);
	}

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + pushRaxSz + prolSz;
	const uint64_t jmpHolderCurAddr = m_trampoline + m_trampolineSz - 8;
	{
		auto jmpToProl = makeMinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
		m_disasm.writeEncoding(jmpToProl);
	}

	auto makeJmpFn = std::bind(&x64Detour::makeMinimumJump, this, _1, _2, jmpHolderCurAddr);
	uint64_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
	PLH::insts_t jmpTblEntries = relocateTrampoline(prologue, jmpTblStart, delta, getMinJmpSize(), 
		makeJmpFn, instsNeedingReloc, instsNeedingEntry);
	if (jmpTblEntries.size() > 0)
		return jmpTblEntries;
	else
		return std::nullopt;
}