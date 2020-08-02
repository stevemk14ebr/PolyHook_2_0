//
// Created by steve on 7/5/17.
//
#include "polyhook2/CapstoneDisassembler.hpp"

PLH::CapstoneDisassembler::CapstoneDisassembler(const PLH::Mode mode) : ADisassembler(mode) {
	const cs_mode csMode = (mode == PLH::Mode::x64 ? CS_MODE_64 : CS_MODE_32);
	if (cs_open(CS_ARCH_X86, csMode, &m_capHandle) != CS_ERR_OK) {
		m_capHandle = NULL;
		Log::log("Failed to initialize capstone", ErrorLevel::SEV);
	}

	cs_option(m_capHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

PLH::CapstoneDisassembler::~CapstoneDisassembler() {
	if (m_capHandle)
		cs_close(&m_capHandle);
	m_capHandle = NULL;
}

PLH::insts_t
PLH::CapstoneDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End, const MemAccessor& accessor) {
	cs_insn* insInfo = cs_malloc(m_capHandle);
	insts_t insVec;
	m_branchMap.clear();

	uint64_t size = End - start;
	assert(size > 0);
	if (size <= 0)
		return insVec;

	// copy potentially remote memory to local buffer
	uint8_t* buf = new uint8_t[(uint32_t)size];

	// bufAddr updated by cs_disasm_iter
	uint64_t bufAddr = (uint64_t)buf;
	accessor.mem_copy((uint64_t)buf, firstInstruction, size);

	while (cs_disasm_iter(m_capHandle, (const uint8_t**)&bufAddr, (size_t*)&size, &start, insInfo)) {
		// Set later by 'SetDisplacementFields'
		Instruction::Displacement displacement = {};
		displacement.Absolute = 0;

		Instruction inst(insInfo->address,
						 displacement,
						 0,
						 false,
			             false,
						 insInfo->bytes,
						 insInfo->size,
						 insInfo->mnemonic,
						 insInfo->op_str,
						 m_mode);

		setDisplacementFields(inst, insInfo);
		insVec.push_back(inst);

		// searches instruction vector and updates references
		addToBranchMap(insVec, inst);

		if (isFuncEnd(inst))
			break;
	}
	delete[] buf;
	cs_free(insInfo, 1);
	return insVec;
}

/**If an instruction is a jmp/call variant type this will set it's displacement fields to the
 * appropriate values. All other types of instructions are ignored as no-op. More specifically
 * this determines if an instruction is a jmp/call variant, and then further if it is is jumping via
 * memory or immediate, and then finally if that mem/imm is encoded via a displacement relative to
 * the instruction pointer, or directly to an absolute address**/
void PLH::CapstoneDisassembler::setDisplacementFields(PLH::Instruction& inst, const cs_insn* capInst) const {
	cs_x86 x86 = capInst->detail->x86;
	const bool branches = hasGroup(capInst, x86_insn_group::X86_GRP_JUMP) || hasGroup(capInst, x86_insn_group::X86_GRP_CALL);
	inst.setBranching(branches);

	for (uint_fast32_t j = 0; j < x86.op_count; j++) {
		cs_x86_op op = x86.operands[j];
		if (op.type == X86_OP_MEM) {
			// Are we relative to instruction pointer?
			// mem are types like jmp [rip + 0x4] where location is dereference-d

			bool needsDisplacement = false;
			if ((hasGroup(capInst, x86_insn_group::X86_GRP_JUMP) && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) ||
				(hasGroup(capInst, x86_insn_group::X86_GRP_CALL) && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x15) ||

				// skip rex prefix
			    (hasGroup(capInst, x86_insn_group::X86_GRP_JUMP) && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x25) ||
				(hasGroup(capInst, x86_insn_group::X86_GRP_CALL) && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x25)
				)
			{
				// far jmp 0xff, 0x25, holder jmp [0xdeadbeef]
				inst.setIndirect(true);

				if (m_mode == Mode::x86) {
					needsDisplacement = true;
				}
			} 

			if (op.mem.base == getIpReg()) {
				const uint8_t offset = x86.encoding.disp_offset;
				const uint8_t size = std::min<uint8_t>(x86.encoding.disp_size,
					std::min<uint8_t>(sizeof(uint64_t), (uint8_t)(capInst->size - x86.encoding.disp_offset)));

				// it's relative, set immDest to max to trigger later check
				copyDispSx(inst, offset, size, std::numeric_limits<int64_t>::max());
			} else if (needsDisplacement) {
				const uint8_t offset = x86.encoding.disp_offset;
				const uint8_t size = std::min<uint8_t>(x86.encoding.disp_size,
					std::min<uint8_t>(sizeof(uint64_t), (uint8_t)(capInst->size - x86.encoding.disp_offset)));

				// it's absolute
				copyDispSx(inst, offset, size, op.mem.disp);
			}

			break;
		} else if (op.type == X86_OP_IMM) {
			// IMM types are like call 0xdeadbeef where they jmp straight to some location
			if (!branches)
				break;

			const uint8_t offset = x86.encoding.imm_offset;
			const uint8_t size = std::min<uint8_t>(x86.encoding.imm_size,
												   std::min<uint8_t>(sizeof(uint64_t), (uint8_t)(capInst->size - x86.encoding.imm_offset)));

			copyDispSx(inst, offset, size, op.imm);
			break;
		}
	}
}

/**Copies the displacement bytes from memory, and sign extends these values if necessary**/
void PLH::CapstoneDisassembler::copyDispSx(PLH::Instruction& inst,
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

	const uint64_t mask = (1ULL << (size * 8 - 1));
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