#include "headers/Detour/ADetour.hpp"

PLH::Detour::Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis)
: m_disasm(dis) {
	assert(fnAddress != 0 && fnCallback != 0);
	m_fnAddress = fnAddress;
	m_fnCallback = fnCallback;
	m_trampoline = (uint64_t)NULL;
	m_trampolineSz = (uint16_t)NULL;
	m_hooked = false;
	m_userTrampVar = userTrampVar;
}

PLH::Detour::Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis)
: Detour((uint64_t)fnAddress, (uint64_t)fnCallback, userTrampVar, dis) {}

PLH::Detour::~Detour() {
	try {
		unHook();
	}
	catch(...) {
		std::cout << "Unhooking failed \n";
	}
}

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

bool PLH::Detour::followJmp(PLH::insts_t& functionInsts, const uint8_t curDepth, const uint8_t depth) {
	if (functionInsts.size() <= 0 || curDepth >= depth) {
		ErrorLog::singleton().push("Couldn't decompile instructions at followed jmp", ErrorLevel::WARN);
		return false;
	}

	// not a branching instruction, no resolution needed
	if (!functionInsts.front().isBranching()) {
		return true;
	}

	// might be a mem type like jmp rax, not supported
	if (!functionInsts.front().hasDisplacement()) {
		ErrorLog::singleton().push("Branching instruction without displacement encountered", ErrorLevel::WARN);
		return false;
	}

	uint64_t dest = functionInsts.front().getDestination();
	functionInsts = m_disasm.disassemble(dest, dest, dest + 100);
	return followJmp(functionInsts, curDepth + 1); // recurse
}

bool PLH::Detour::expandProlSelfJmps(insts_t& prol,
									 const insts_t& func,
									 uint64_t& minProlSz,
									 uint64_t& roundProlSz) {
	const uint64_t prolStart = prol.front().getAddress();
	branch_map_t branchMap = m_disasm.getBranchMap();

	for (size_t i = 0; i < prol.size(); i++) {
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

bool PLH::Detour::buildRelocationList(insts_t& prologue, const uint64_t roundProlSz, const int64_t delta, PLH::insts_t& instsNeedingEntry, PLH::insts_t& instsNeedingReloc) {
	assert(instsNeedingEntry.size() == 0);
	assert(instsNeedingReloc.size() == 0);
	assert(prologue.size() > 0);

	const uint64_t prolStart = prologue.front().getAddress();

	for (auto& inst : prologue) {
		// todo: fix
		
		auto isBranching = inst.isBranching() && inst.hasDisplacement();
		auto isRelative = inst.hasDisplacement() && inst.isDisplacementRelative();
		if ((isBranching || isRelative) &&
			(inst.getDestination() < prolStart ||
			inst.getDestination() > prolStart + roundProlSz)) {

			// can inst just be re-encoded or do we need a tbl entry
			const uint8_t dispSzBits = (uint8_t)inst.getDispSize() * 8;
			const uint64_t maxInstDisp = (uint64_t)(std::pow(2, dispSzBits) / 2.0 - 1.0); // 2^bitSz give max val, /2 and -1 because signed ex (int8_t [-128, 127] = [2^8 / 2, 2^8 / 2 - 1]
			if ((uint64_t)std::llabs(delta) > maxInstDisp) {
				instsNeedingEntry.push_back(inst);
			} else {
				instsNeedingReloc.push_back(inst);
			}
		}

		// data operations (duplicated because clearer)
		if (!inst.isBranching() && inst.hasDisplacement()) {
			const uint8_t dispSzBits = (uint8_t)inst.getDispSize() * 8;
			const uint64_t maxInstDisp = (uint64_t)(std::pow(2, dispSzBits) / 2.0 - 1.0); 
			if ((uint64_t)std::llabs(delta) > maxInstDisp) {
				/*EX: 48 8d 0d 96 79 07 00    lea rcx, [rip + 0x77996]
				If instruction is moved beyond displacement field width
				we can't fix the load. TODO: generate equivalent load
				with asmjit and insert it at position
				*/
				ErrorLog::singleton().push("Cannot fixup IP relative data operation, relocation beyond displacement size", ErrorLevel::SEV);
				return false;
			}else {
				instsNeedingReloc.push_back(inst);
			}
		}
	}
	return true;
}

PLH::insts_t PLH::Detour::relocateTrampoline(insts_t& prologue, uint64_t jmpTblStart, const int64_t delta, const uint8_t jmpSz, 
                       std::function<PLH::insts_t(const uint64_t, const uint64_t)> makeJmp, 
                       const PLH::insts_t& instsNeedingReloc, const PLH::insts_t& instsNeedingEntry) { 
  uint64_t jmpTblCurAddr = jmpTblStart; 
  insts_t jmpTblEntries; 
  for (auto& inst : prologue) { 
    if (std::find(instsNeedingEntry.begin(), instsNeedingEntry.end(), inst) != instsNeedingEntry.end()) { 
      assert(inst.hasDisplacement()); 
      // make an entry pointing to where inst did point to 
      auto entry = makeJmp(jmpTblCurAddr, inst.getDestination()); 
       
      // move inst to trampoline and point instruction to entry 
      inst.setAddress(inst.getAddress() + delta); 
      inst.setDestination(jmpTblCurAddr); 
      jmpTblCurAddr += jmpSz; 
       
      m_disasm.writeEncoding(entry); 
      jmpTblEntries.insert(jmpTblEntries.end(), entry.begin(), entry.end()); 
    } else if (std::find(instsNeedingReloc.begin(), instsNeedingReloc.end(), inst) != instsNeedingReloc.end()) { 
      assert(inst.hasDisplacement()); 
       
      const uint64_t instsOldDest = inst.getDestination(); 
      inst.setAddress(inst.getAddress() + delta); 
      inst.setDestination(instsOldDest); 
    } else { 
      inst.setAddress(inst.getAddress() + delta); 
    } 
     
    m_disasm.writeEncoding(inst); 
  } 
  return jmpTblEntries; 
} 

bool PLH::Detour::unHook() {
	if (m_hooked) {
		MemoryProtector prot(m_fnAddress, PLH::calcInstsSz(m_originalInsts), ProtFlag::R | ProtFlag::W | ProtFlag::X);
		m_disasm.writeEncoding(m_originalInsts);
		
		if (m_trampoline != (uint64_t)NULL) {
			delete[](char*)m_trampoline;
			m_trampoline = (uint64_t)NULL;
		}

		if (m_userTrampVar != NULL) {
			*m_userTrampVar = (uint64_t)NULL;
			m_userTrampVar = NULL;
		}
		
		m_hooked = false;
		return true;
	}
	return false;
}
