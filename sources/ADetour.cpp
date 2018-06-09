#include "headers/Detour/ADetour.hpp"

std::map<uint64_t, PLH::Trampoline> PLH::Detour::m_trampolines;

std::optional<PLH::insts_t> PLH::Detour::calcNearestSz(const PLH::insts_t& functionInsts, const uint64_t prolOvrwStartOffset,
	uint64_t& prolOvrwEndOffset) {

	uint64_t     prolLen = 0;
	PLH::insts_t instructionsInRange;

	// count instructions until at least length needed or func end
	for (auto inst : functionInsts) {
		if (prolLen >= prolOvrwStartOffset)
			break;

		if (m_disasm.isFuncEnd(inst))
			break;

		prolLen += inst.size();
		instructionsInRange.push_back(inst);
	}

	if (prolLen >= prolOvrwStartOffset) {
		prolOvrwEndOffset = prolLen;
		return instructionsInRange;
	}
	return std::nullopt;
}

bool PLH::Detour::followProlJmp(PLH::insts_t& functionInsts,const uint8_t curDepth, const uint8_t depth) {
	if (functionInsts.size() <= 0 || curDepth >= depth)
		return false;

	// not a branching instruction, no resolution needed
	if (!functionInsts.at(0).hasDisplacement()) {
		m_fnAddress = functionInsts.at(0).getAddress();
		return true;
	}
	
	uint64_t dest = functionInsts.at(0).getDestination();
	functionInsts = m_disasm.disassemble(dest, dest, dest + 100);
	followProlJmp(functionInsts, curDepth + 1); // recurse
}

std::optional<PLH::insts_t> PLH::Detour::expandProl(const insts_t& prolInsts,const insts_t& funcInsts, uint64_t& minSz, uint64_t& roundedSz, const uint8_t jmpSz, bool& expanded) {
	assert(prolInsts.size() > 0 && funcInsts.size() > 0);
	assert(minSz <= roundedSz);
	assert(jmpSz > 0);
	expanded = false;

	/* look for instructions that point back into prologue, if they do
	then expand prologue to make room for the prologue jump table. Loop
	bound is modified during loop*/
	PLH::branch_map_t branchMap = m_disasm.getBranchMap();
	insts_t prologue = prolInsts;
	int idx = 0;
	
	std::cout << "is: " << minSz << " " << roundedSz << std::endl;
	for (uint64_t byteCnt = 0; byteCnt < roundedSz; idx++)
	{
		auto inst = prologue.at(idx);
		byteCnt += inst.size();
		if (branchMap.find(inst.getAddress()) == branchMap.end())
			continue; 
		
		expanded = true;
		minSz += jmpSz;
		auto prologueOpt = calcNearestSz(funcInsts, minSz, roundedSz);
		if (!prologueOpt) {
			ErrorLog::singleton().push("Function prologue to small to expand more", ErrorLevel::SEV);
			return std::nullopt;
		}
		prologue = *prologueOpt;
	}
	
	std::cout << "Expanded: " << minSz << " " << roundedSz << std::endl;
	return prologue;
}
