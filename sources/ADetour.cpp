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
	return followProlJmp(functionInsts, curDepth + 1); // recurse
}

void PLH::Detour::copyTrampolineProl(insts_t& prologue, const uint64_t trampStart, unsigned char* trampoline, const uint64_t roundProlSz)
{
	uint64_t trampAddr = trampStart;
	for (auto& inst : prologue) {
		uint64_t instDest = inst.getDestination();
		inst.setAddress(trampAddr);

		// relocate if it doesn't point inside prologue 
		if (inst.getDestination() < (uint64_t)trampoline ||
			inst.getDestination() > (uint64_t)trampoline + roundProlSz) {
			inst.setDestination(instDest);
		}

		trampAddr += inst.size();
		m_disasm.writeEncoding(inst);
	}
}