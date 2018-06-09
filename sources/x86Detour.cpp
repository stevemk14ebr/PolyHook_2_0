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

	return { Instruction(address, disp, 1, true, bytes, "jmp", ss.str()) };
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

	uint64_t prolJmpLen = getJmpSize(); // min size of patches that may-split instructions
	uint64_t prolOrigLen = prolJmpLen; // size of original non-split instructions

	// find the prologue section we will overwrite with jmp + zero or more nops
	auto prologueOpt = calcNearestSz(insts, prolJmpLen, prolOrigLen);
	if (!prologueOpt) {
		ErrorLog::singleton().push("Function too small to hook safely!", ErrorLevel::SEV);
		return false;
	}
	assert(prolOrigLen >= prolJmpLen);
	insts_t prologue = *prologueOpt;

	// expand prologue for jmp tbl if necessary
	bool needProlJmpTbl = false;
	prologueOpt = expandProl(prologue, insts, prolJmpLen, prolOrigLen, getJmpSize(), needProlJmpTbl);
	assert(prolOrigLen >= prolJmpLen);
	prologue = *prologueOpt;
	
	char* trampoline = new char[prolOrigLen];

	insts_t prolJmps;
	if (needProlJmpTbl) {
		PLH::branch_map_t branchMap = m_disasm.getBranchMap();

		const uint64_t prolStart = prologue.at(0).getAddress();
		const uint64_t tblStart = prolStart + getJmpSize();
		int tblIdx = 0;
		for (int i = 0; i < prologue.size(); i++)
		{
			auto inst = prologue.at(i);
			if (branchMap.find(inst.getAddress()) == branchMap.end())
				continue;

			// the (long) jmp that goes from prologue to trampoline
			const uint64_t entryAddr = tblStart + (tblIdx++) * getJmpSize();
			auto jmpEntry = makeJmp(entryAddr, (uint64_t)trampoline + (inst.getAddress() - prolStart));
			prolJmps.insert(prolJmps.end(), jmpEntry.begin(), jmpEntry.end());

			// point all jmp sources to the tbl entry instead of the to-be-moved instruction
			insts_t branchSources = branchMap.at(inst.getAddress());
			for (auto& branch : branchSources) {
				branch.setDestination(entryAddr);
			}
		}
	}

	std::cout << "Prologue to overwrite:" << std::endl << prologue << std::endl;
	std::cout << "Prologue jump table:" << std::endl << prolJmps << std::endl;
	return true;
}

bool PLH::x86Detour::unHook() {
	return true;
}