//
// Created by steve on 7/5/17.
//
#include "headers/CapstoneDisassembler.hpp"

PLH::insts_t
PLH::CapstoneDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End) {
	cs_insn* InsInfo = cs_malloc(m_capHandle);
	insts_t InsVec;
	m_branchMap.clear();

	uint64_t Size = End - start;
	while (cs_disasm_iter(m_capHandle, (const uint8_t**)&firstInstruction, (size_t*)&Size, &start, InsInfo)) {
		// Set later by 'SetDisplacementFields'
		Instruction::Displacement displacement;
		displacement.Absolute = 0;

		Instruction Inst(InsInfo->address,
						 displacement,
						 0,
						 false,
						 InsInfo->bytes,
						 InsInfo->size,
						 InsInfo->mnemonic,
						 InsInfo->op_str,
						 m_mode);

		setDisplacementFields(Inst, InsInfo);
		InsVec.push_back(Inst);

		// update jump map if the instruction is jump/call
		if (Inst.isBranching() && Inst.hasDisplacement()) {
			// search back, check if new instruction points to older ones (one to one)
			auto destInst = std::find_if(InsVec.begin(), InsVec.end(), [=] (const Instruction& oldIns) {
				return oldIns.getAddress() == Inst.getDestination();
			});

			if (destInst != InsVec.end()) {
				updateBranchMap(destInst->getAddress(), Inst);
			}
		}

		// search forward, check if old instructions now point to new one (many to one possible)
		for (const Instruction& oldInst : InsVec) {
			if (oldInst.isBranching() && oldInst.hasDisplacement() && oldInst.getDestination() == Inst.getAddress()) {
				updateBranchMap(Inst.getAddress(), oldInst);
			}
		}
	}
	cs_free(InsInfo, 1);
	return InsVec;
}

/**Write the raw bytes of the given instruction into the memory specified by the
 * instruction's address. If the address value of the instruction has been changed
 * since the time it was decoded this will copy the instruction to a new memory address.
 * This will not automatically do any code relocation, all relocation logic should
 * first modify the byte array, and then call write encoding, proper order to relocate
 * an instruction should be disasm instructions -> set relative/absolute displacement() ->
 * writeEncoding(). It is done this way so that these operations can be made transactional**/
void PLH::CapstoneDisassembler::writeEncoding(const PLH::Instruction& instruction) const {
	memcpy((void*)instruction.getAddress(), &instruction.getBytes()[0], instruction.size());
}

/**If an instruction is a jmp/call variant type this will set it's displacement fields to the
 * appropriate values. All other types of instructions are ignored as no-op. More specifically
 * this determines if an instruction is a jmp/call variant, and then further if it is is jumping via
 * memory or immediate, and then finally if that mem/imm is encoded via a displacement relative to
 * the instruction pointer, or directly to an absolute address**/
void PLH::CapstoneDisassembler::setDisplacementFields(PLH::Instruction& inst, const cs_insn* capInst) const {
	cs_x86 x86 = capInst->detail->x86;
	bool branches = hasGroup(capInst, x86_insn_group::X86_GRP_JUMP) || hasGroup(capInst, x86_insn_group::X86_GRP_CALL);
	inst.setBranching(branches);

	for (uint_fast32_t j = 0; j < x86.op_count; j++) {
		cs_x86_op op = x86.operands[j];
		if (op.type == X86_OP_MEM) {
			// Are we relative to instruction pointer?
			// mem are types like jmp [rip + 0x4] where location is dereference-d
			if (op.mem.base != getIpReg()) {
				if (hasGroup(capInst, x86_insn_group::X86_GRP_JUMP) && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) {
					// far jmp 0xff, 0x25, holder jmp [0xdeadbeef]
					inst.setAbsoluteDisplacement(*(uint32_t*)op.mem.disp);
				}
				continue;
			}

			const uint8_t Offset = x86.encoding.disp_offset;
			const uint8_t Size = std::min<uint8_t>(x86.encoding.disp_size,
												   std::min<uint8_t>(sizeof(uint64_t), (uint8_t)(capInst->size - x86.encoding.disp_offset)));

			// it's relative, set immDest to max to trigger later check
			copyDispSX(inst, Offset, Size, std::numeric_limits<int64_t>::max());
			break;
		} else if (op.type == X86_OP_IMM) {
			// IMM types are like call 0xdeadbeef where they jmp straight to some location
			if (!branches)
				break;

			const uint8_t Offset = x86.encoding.imm_offset;
			const uint8_t Size = std::min<uint8_t>(x86.encoding.imm_size,
												   std::min<uint8_t>(sizeof(uint64_t), (uint8_t)(capInst->size - x86.encoding.imm_offset)));

			copyDispSX(inst, Offset, Size, op.imm);
			break;
		}
	}
}

/**Copies the displacement bytes from memory, and sign extends these values if necessary**/
void PLH::CapstoneDisassembler::copyDispSX(PLH::Instruction& inst,
										   const uint8_t offset,
										   const uint8_t size,
										   const int64_t immDestination) const {
	/* Sign extension necessary because we are storing numbers (possibly) smaller than int64_t that may be negative.
	 * If we did not do this, then the sign bit would be in the incorrect place for an int64_t.
	 * 1 << (Size*8-1) dynamically calculates the position of the sign bit (furthest left) (our byte mask)
	 * the Size*8 gives us the size in bits, i do -1 because zero based. Then left shift to set that bit to one.
	 * Then & that with the calculated mask to check if the sign bit is set in the retrieved displacement,
	 * the result will be positive if sign bit is set (negative displacement)
	 * and 0 when sign bit not set (positive displacement)*/
	int64_t displacement = 0;
	if (offset + size > (uint8_t)inst.getBytes().size()) {
		__debugbreak();
		return;
	}

	assert(offset + size <= (uint8_t)inst.getBytes().size());
	memcpy(&displacement, &inst.getBytes()[offset], size);

	uint64_t mask = (1ULL << (size * 8 - 1));
	if (displacement & (1ULL << (size * 8 - 1))) {
		/* sign extend if negative, requires that bits above Size*8 are zero,
		 * if bits are not zero use x = x & ((1U << b) - 1) where x is a temp for displacement
		 * and b is Size*8*/
		displacement = (displacement ^ mask) -
			mask; //xor clears sign bit, subtraction makes number negative again but in the int64 range
	}

	inst.setDisplacementOffset(offset);

	/* When the retrieved displacement is < immDestination we know that the base address is included
	 * in the destinations calculation. By definition this means it is relative. Otherwise it is absolute*/
	if (displacement < immDestination) {
		inst.setRelativeDisplacement(displacement);
	} else {
		if (((uint64_t)displacement) != ((uint64_t)immDestination))
			__debugbreak();
		assert(((uint64_t)displacement) == ((uint64_t)immDestination));
		inst.setAbsoluteDisplacement((uint64_t)displacement);
	}
}

bool PLH::CapstoneDisassembler::isConditionalJump(const PLH::Instruction& instruction) const {
	// http://unixwiz.net/techtips/x86-jumps.html
	if (instruction.size() < 1)
		return false;

	std::vector<uint8_t> bytes = instruction.getBytes();
	if (bytes[0] == 0x0F && instruction.size() > 1) {
		if (bytes[1] >= 0x80 && bytes[1] <= 0x8F)
			return true;
	}

	if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
		return true;

	if (bytes[0] == 0xE3)
		return true;

	return false;
}

bool PLH::CapstoneDisassembler::isFuncEnd(const PLH::Instruction& instruction) const {
	// TODO: more?
	/*
	* 0xABABABAB : Used by Microsoft's HeapAlloc() to mark "no man's land" guard bytes after allocated heap memory
	* 0xABADCAFE : A startup to this value to initialize all free memory to catch errant pointers
	* 0xBAADF00D : Used by Microsoft's LocalAlloc(LMEM_FIXED) to mark uninitialised allocated heap memory
	* 0xBADCAB1E : Error Code returned to the Microsoft eVC debugger when connection is severed to the debugger
	* 0xBEEFCACE : Used by Microsoft .NET as a magic number in resource files
	* 0xCCCCCCCC : Used by Microsoft's C++ debugging runtime library to mark uninitialised stack memory
	* 0xCDCDCDCD : Used by Microsoft's C++ debugging runtime library to mark uninitialised heap memory
	* 0xDDDDDDDD : Used by Microsoft's C++ debugging heap to mark freed heap memory
	* 0xDEADDEAD : A Microsoft Windows STOP Error code used when the user manually initiates the crash.
	* 0xFDFDFDFD : Used by Microsoft's C++ debugging heap to mark "no man's land" guard bytes before and after allocated heap memory
	* 0xFEEEFEEE : Used by Microsoft's HeapFree() to mark freed heap memory
	*/
	return instruction.getMnemonic() == "ret";
}