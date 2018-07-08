//
// Created by steve on 7/5/17.
//
#include "headers/Detour/x86Detour.hpp"

PLH::x86Detour::x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

PLH::x86Detour::x86Detour(const char* fnAddress, const char* fnCallback, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, dis) {

}

PLH::Mode PLH::x86Detour::getArchType() const {
    return PLH::Mode::x86;
}

PLH::insts_t PLH::x86Detour::makeJmp(const uint64_t address, const uint64_t destination) const {
	Instruction::Displacement disp;
	disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destination, 5);

	std::vector<uint8_t> bytes(5);
	bytes[0] = 0xE9;
	memcpy(&bytes[1], &disp.Relative, 4);

	std::stringstream ss;
	ss << std::hex << destination;

	return { Instruction(address, disp, 1, true, bytes, "jmp", ss.str(), Mode::x86) };
}

uint8_t PLH::x86Detour::getJmpSize() const {
	return 5;
}

bool PLH::x86Detour::hook() {
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

	std::cout << "Prologue to overwrite:" << std::endl << prologue << std::endl;

	{   // copy all the prologue stuff to trampoline
		auto makeJmpFn = std::bind(&x86Detour::makeJmp, this, _1, _2);
		auto jmpTblOpt = makeTrampoline(prologue, roundProlSz, getJmpSize(), makeJmpFn);

		std::cout << "Trampoline:" << std::endl << m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz) << std::endl;
		if (jmpTblOpt)
			std::cout << "Trampoline Jmp Tbl:" << std::endl << *jmpTblOpt << std::endl;
	}

	MemoryProtector prot(m_fnAddress, roundProlSz, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	auto prolJmp = makeJmp(m_fnAddress, m_fnCallback);
	m_disasm.writeEncoding(prolJmp);

	// Nop the space between jmp and end of prologue
	const uint8_t nopSz = (uint8_t) (roundProlSz - minProlSz);
	std::memset((char*)(m_fnAddress + minProlSz), 0x90, (size_t)nopSz);

	m_hooked = true;
	return true;
}

bool PLH::x86Detour::unHook() {
	return true;
}