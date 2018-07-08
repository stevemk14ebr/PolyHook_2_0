#include "headers/Detour/ADetour.hpp"

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

bool PLH::Detour::followJmp(PLH::insts_t& functionInsts,const uint8_t curDepth, const uint8_t depth) {
	if (functionInsts.size() <= 0 || curDepth >= depth)
		return false;

	// not a branching instruction, no resolution needed
	if (!functionInsts.front().hasDisplacement()) {
		return true;
	}
	
	uint64_t dest = functionInsts.front().getDestination();
	functionInsts = m_disasm.disassemble(dest, dest, dest + 100);
	return followJmp(functionInsts, curDepth + 1); // recurse
}