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

	std::vector<uint8_t> raxBytes = { 0x50 };
	auto pushRax = Instruction(curInstAddress, zeroDisp, 0, false, 
								raxBytes, "push", "rax", Mode::x64);
	curInstAddress += pushRax.size();

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

	return { pushRax, movRax, xchgRspRax, ret };
}

uint8_t PLH::x64Detour::getMinJmpSize() const {
	return 6;
}

uint8_t PLH::x64Detour::getPrefJmpSize() const {
	return 16;
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