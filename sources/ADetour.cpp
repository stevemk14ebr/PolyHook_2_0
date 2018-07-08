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

bool PLH::Detour::buildProlJmpTbl(insts_t& prol,
	const insts_t& func,
	uint64_t& minProlSz,
	uint64_t& roundProlSz)
{
	const uint64_t prolStart = prol.front().getAddress();
	branch_map_t branchMap = m_disasm.getBranchMap();

	for (size_t i = 0; i < prol.size(); i++)
	{
		auto inst = prol.at(i);

		// is there a jump pointing at the current instruction?
		if (branchMap.find(inst.getAddress()) == branchMap.end())
			continue;

		insts_t srcs = branchMap.at(inst.getAddress());
		uint64_t maxAddr = 0;
		for (const auto& src : srcs) {
			const uint64_t srcEndAddr = src.getAddress() + src.size();
			if (srcEndAddr > maxAddr)
				maxAddr = srcEndAddr;
		}

		minProlSz = maxAddr - prolStart;

		// expand prol by one entry size, may fail if prol to small
		auto prolOpt = calcNearestSz(func, minProlSz, roundProlSz);
		if (!prolOpt)
			return false;
		prol = *prolOpt;
	}

	return true;
}