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
	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100);
	if (insts.size() <= 0) {
		ErrorLog::singleton().push("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followProlJmp(insts)) {
		ErrorLog::singleton().push("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	std::cout << "Originial function:" << std::endl << insts << std::endl;

	uint64_t minProlSz = getJmpSize(); // min size of patches that may-split instructions
	uint64_t roundProlSz = minProlSz; // size of original non-split instructions

	// find the prologue section we will overwrite with jmp + zero or more nops
	auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
	if (!prologueOpt) {
		ErrorLog::singleton().push("Function too small to hook safely!", ErrorLevel::SEV);
		return false;
	}
	assert(roundProlSz >= minProlSz);
	insts_t prologue = *prologueOpt;

	// expand prologue for jmp tbl if necessary
	bool needProlJmpTbl = false;
	prologueOpt = expandProl(prologue, insts, minProlSz, roundProlSz, getJmpSize(), needProlJmpTbl);
	assert(roundProlSz >= minProlSz);
	prologue = *prologueOpt;
	
	const uint64_t trampolineSz = roundProlSz;
	unsigned char* trampoline = new unsigned char[(int)trampolineSz];

	insts_t prolJmps;
	insts_t prolJmpsToFix;
	buildProlJmpTbl(prologue, prolJmps, prolJmpsToFix, (uint64_t)trampoline, getJmpSize(), std::bind(&x86Detour::makeJmp, this, _1, _2));

	std::cout << "Prologue to overwrite:" << std::endl << prologue << std::endl;
	std::cout << "Prologue jump table:" << std::endl << prolJmps << std::endl;

	{// copy all the prologue stuff to trampoline
		
		uint64_t trampolineAddr = (uint64_t)trampoline;
		MemoryProtector prot(trampolineAddr, trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, false);
		for (auto& inst : prologue) {
			inst.setAddress(trampolineAddr);
			trampolineAddr += inst.size();
			m_disasm.writeEncoding(inst);
		}
	}

	std::cout << m_disasm.disassemble((uint64_t)trampoline, (uint64_t)trampoline, (uint64_t)trampoline + trampolineSz) << std::endl;
	return true;
}

bool PLH::x86Detour::unHook() {
	return true;
}