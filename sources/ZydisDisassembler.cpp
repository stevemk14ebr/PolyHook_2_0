#include "polyhook2/ZydisDisassembler.hpp"

#include <deque>

#include "polyhook2/ErrorLog.hpp"

PLH::ZydisDisassembler::ZydisDisassembler(PLH::Mode mode) : m_decoder(new ZydisDecoder()), m_formatter(new ZydisFormatter()) {
	m_mode = mode;
	if (ZYAN_FAILED(ZydisDecoderInit(m_decoder,
									 (mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
									 (mode == PLH::Mode::x64) ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32))) {
		Log::log("Failed to initialize zydis decoder", ErrorLevel::SEV);
		return;
	}

	if (ZYAN_FAILED(ZydisFormatterInit(m_formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
		Log::log("Failed to initialize zydis formatter", ErrorLevel::SEV);
		return;
	}

	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

PLH::ZydisDisassembler::~ZydisDisassembler() {
	if (m_decoder) {
		delete m_decoder;
		m_decoder = nullptr;
	}

	if (m_formatter) {
		delete m_formatter;
		m_formatter = nullptr;
	}
}

PLH::insts_t PLH::ZydisDisassembler::disassemble(
    uint64_t firstInstruction,
    uint64_t start,
    uint64_t end,
    const MemAccessor& accessor
) {
	insts_t insVec;
//	m_branchMap.clear();

	uint64_t size = end - start;
	assert(size > 0);
	if (size <= 0) {
		return insVec;
	}

	// copy potentially remote memory to local buffer
	size_t read = 0;
	auto* buf = new uint8_t[(uint32_t)size];
	if (!accessor.safe_mem_read(firstInstruction, (uint64_t)buf, size, read)) {
		delete[] buf;
		return insVec;
	}
	ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecodedInstruction insInfo;
	uint64_t offset = 0;
	bool endHit = false;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(m_decoder, (char*) (buf + offset), (ZyanUSize) (read - offset), &insInfo, decoded_operands))) {
        Instruction::Displacement displacement = {};
		displacement.Absolute = 0;

		uint64_t address = start + offset;

		std::string opstr;
		if (!getOpStr(&insInfo, decoded_operands, address, &opstr)){
			break;
        }


		Instruction inst(address,
						 displacement,
						 0,
						 false,
						 false,
						 (uint8_t*) ((unsigned char*) buf + offset),
						 insInfo.length,
						 ZydisMnemonicGetString(insInfo.mnemonic),
						 opstr,
						 m_mode);

		setDisplacementFields(inst, &insInfo, decoded_operands);
		if (endHit && !isPadBytes(inst)) {
			break;
        }

		for (int i = 0; i < insInfo.operand_count; i++) {
			auto op = decoded_operands[i];
			if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type == ZYDIS_MEMOP_TYPE_MEM && op.mem.disp.has_displacement && op.mem.base == ZYDIS_REGISTER_NONE && op.mem.segment != ZYDIS_REGISTER_DS && inst.isIndirect()) {
				inst.setIndirect(false);
			}
		}

		insVec.push_back(inst);

		// searches instruction vector and updates references
		addToBranchMap(insVec, inst);
		if (isFuncEnd(inst, start == address)){
			endHit = true;
        }

		offset += insInfo.length;
	}

	delete[] buf;
	return insVec;
}

std::optional<PLH::Instruction> PLH::ZydisDisassembler::disassemble_one_inst(
	uint64_t firstInstruction,
	const MemAccessor& accessor
) {
	uint64_t size = 100;
	// copy potentially remote memory to local buffer
	size_t read = 0;
	auto* buf = new uint8_t[(uint32_t)size];
	if (!accessor.safe_mem_read(firstInstruction, (uint64_t)buf, size, read)) {
		delete[] buf;
		return std::nullopt;
	}
	ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecodedInstruction insInfo;

	if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(m_decoder, (char*)(buf), (ZyanUSize)(read), &insInfo, decoded_operands))) {
		Instruction::Displacement displacement = {};
		displacement.Absolute = 0;

		std::string opstr;
		if (!getOpStr(&insInfo, decoded_operands, firstInstruction, &opstr)) {
			delete[] buf;
			return std::nullopt;
		}

		Instruction inst(firstInstruction,
			displacement,
			0,
			false,
			false,
			buf,
			insInfo.length,
			ZydisMnemonicGetString(insInfo.mnemonic),
			opstr,
			m_mode);

		setDisplacementFields(inst, &insInfo, decoded_operands);


		for (int i = 0; i < insInfo.operand_count; i++) {
			auto op = decoded_operands[i];
			if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type == ZYDIS_MEMOP_TYPE_MEM && op.mem.disp.has_displacement && op.mem.base == ZYDIS_REGISTER_NONE && op.mem.segment != ZYDIS_REGISTER_DS && inst.isIndirect()) {
				inst.setIndirect(false);
			}
		}

		delete[] buf;
		return inst;
	}
	return std::nullopt;
}

PLH::insts_t PLH::ZydisDisassembler::disassemble_backward_until_prev_func_end(
	uint64_t startInstruction,
	const MemAccessor& accessor
) {
	//insts_t insVec;
	std::deque<Instruction> insDeque;
	uint64_t batchSzArr[] = { 4, 8, 16, 32, 64 };
	int batchSzArrLen = sizeof(batchSzArr) / sizeof(uint64_t);
	int batchIdx = 0;
	bool foundPrevFuncEdge = false;
	
	while(batchIdx < batchSzArrLen)
	{
		insDeque.clear();

		uint64_t eachBatchSize = batchSzArr[batchIdx];
		Log::log("try with batch size: " + std::to_string(eachBatchSize), ErrorLevel::INFO);

		// copy potentially remote memory to local buffer
		size_t thisBatchCount = 0;
		auto* buf = new uint8_t[(uint32_t)eachBatchSize];
		uint64_t start = startInstruction - eachBatchSize;
		if (!accessor.safe_mem_read(start, (uint64_t)buf, eachBatchSize, thisBatchCount)) {
			delete[] buf;
			break;
		}
		ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
		ZydisDecodedInstruction insInfo;
		uint64_t offset = 0;
		while (thisBatchCount - offset > 0) {
			ZyanStatus decode_status = ZydisDecoderDecodeFull(m_decoder, (char*)(buf + offset), (ZyanUSize)(thisBatchCount - offset), &insInfo, decoded_operands);
			if (ZYAN_FAILED(decode_status))
			{
				offset += 1;
				continue;
			}
			Instruction::Displacement displacement = {};
			displacement.Absolute = 0;

			uint64_t address = start + offset;

			std::string opstr;
			if (!getOpStr(&insInfo, decoded_operands, address, &opstr)) {
				break;
			}

			Instruction inst(address,
				displacement,
				0,
				false,
				false,
				(uint8_t*)((unsigned char*)buf + offset),
				insInfo.length,
				ZydisMnemonicGetString(insInfo.mnemonic),
				opstr,
				m_mode);
			inst.setMnemonicZydis(insInfo.mnemonic);

			setDisplacementFields(inst, &insInfo, decoded_operands);
			setNoOpField(inst, &insInfo, decoded_operands);

			for (int i = 0; i < insInfo.operand_count; i++) {
				auto op = decoded_operands[i];
				if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type == ZYDIS_MEMOP_TYPE_MEM && op.mem.disp.has_displacement && op.mem.base == ZYDIS_REGISTER_NONE && op.mem.segment != ZYDIS_REGISTER_DS && inst.isIndirect()) {
					inst.setIndirect(false);
				}
			}

			insDeque.push_back(inst);

			offset += insInfo.length;
		}

		delete[] buf;

		// check this batch whether we found the edge of the previous function
		int funcEndIdx = -1;
		for(int i = insDeque.size()-1; i >= 0; --i)
		{
			Instruction inst = insDeque.at(i);
			if (inst.getMnemonicZydis() != ZYDIS_MNEMONIC_INT3 /* 0xcc is valid padding bytes between functions */
				&& isFuncEnd(inst))
			{
				foundPrevFuncEdge = true;
				// at this time, the iterator is pointing to func end
				funcEndIdx = i;
				break;
			}
		}


		if (foundPrevFuncEdge)
		{
			// remove it and all items previous to that
			
			for(size_t i = 0; i < funcEndIdx+1; ++i)
			{
				insDeque.pop_front();
			}

			return std::vector(insDeque.begin(), insDeque.end());
		}
		else
		{
			// try a larger batch
			++batchIdx;
		}
	}

	return std::vector(insDeque.begin(), insDeque.end());
}

bool PLH::ZydisDisassembler::getOpStr(ZydisDecodedInstruction* pInstruction, const ZydisDecodedOperand* decoded_operands, uint64_t addr, std::string* pOpStrOut) {
	char buffer[256];
	if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(m_formatter, pInstruction, decoded_operands, pInstruction->operand_count, buffer, sizeof(buffer), addr, ZYAN_NULL))) {
		// remove mnemonic + space (op str is just the right hand side)
		std::string wholeInstStr(buffer);
		*pOpStrOut = wholeInstStr.erase(0, wholeInstStr.find(' ') + 1);
		return true;
	}
	return false;
}

void PLH::ZydisDisassembler::setDisplacementFields(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst, const ZydisDecodedOperand* operands) const {
	inst.setBranching(zydisInst->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE);
	inst.setCalling(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL);

	for (int i = 0; i < zydisInst->operand_count; i++) {
		const ZydisDecodedOperand* const operand = &operands[i];

		// skip implicit operands (r/w effects)
		if (operand->visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
			operand->visibility == ZYDIS_OPERAND_VISIBILITY_INVALID) {
			continue;
        }

		switch (operand->type) {
			case ZYDIS_OPERAND_TYPE_REGISTER: {
				inst.setRegister(operand->reg.value);
				inst.addOperandType(Instruction::OperandType::Register);
				break;
			}
			case ZYDIS_OPERAND_TYPE_UNUSED:
				break;
			case ZYDIS_OPERAND_TYPE_MEMORY: { // Relative to RIP/EIP
				inst.addOperandType(Instruction::OperandType::Displacement);

				if (zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
					inst.setDisplacementOffset(zydisInst->raw.disp.offset);
					inst.setDisplacementSize((uint8_t)(zydisInst->raw.disp.size / 8));
					inst.setRelativeDisplacement(operand->mem.disp.value);
				}

				if ((zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x15) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x25)
					) {

					// is displacement set earlier already?
					if (!inst.hasDisplacement()) {
						// displacement is absolute on x86 mode
						inst.setDisplacementOffset(zydisInst->raw.disp.offset);
						inst.setAbsoluteDisplacement(zydisInst->raw.disp.value);
					}
					inst.setIndirect(true);
				}

				break;
			}
			case ZYDIS_OPERAND_TYPE_POINTER:
				break;
			case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
				inst.addOperandType(Instruction::OperandType::Immediate);

				// is displacement set earlier already?
				if (!inst.hasDisplacement() && zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
					inst.setDisplacementOffset(zydisInst->raw.imm->offset);
                    inst.setDisplacementSize((uint8_t)(zydisInst->raw.imm->size / 8));
                    inst.setRelativeDisplacement(zydisInst->raw.imm->value.s);
					return;
				}

				inst.setImmediate(zydisInst->raw.imm->value.s);
				inst.setImmediateSize(zydisInst->raw.imm->size / 8);

				break;
			}
		}
	}
}

void PLH::ZydisDisassembler::setNoOpField(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst, const ZydisDecodedOperand* operands) const {
	// default value
	inst.setIsNoOp(false);
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_NOP || zydisInst->meta.category == ZYDIS_CATEGORY_NOP)
	{
		inst.setIsNoOp(true);
	}
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_INT3)
	{
		inst.setIsNoOp(true);
	}
	// xchg rAX, rAX
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_XCHG
		&& zydisInst->operand_count == 2
		&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[0].reg.value == operands[1].reg.value)
	{
		inst.setIsNoOp(true);
	}
	// lea     esi, [esi+0]
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_LEA
		&& zydisInst->operand_count == 2
		&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
		&& operands[0].reg.value == operands[1].mem.base
		&& (!operands[1].mem.disp.has_displacement || operands[1].mem.disp.value == 0))
	{
		inst.setIsNoOp(true);
	} 
	// mov edi, edi
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_MOV
		&& zydisInst->operand_count == 2
		&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[0].reg.value == operands[1].reg.value)
	{
		inst.setIsNoOp(true);
	}
	// and eax, -1 (all ones)
	if (zydisInst->mnemonic == ZYDIS_MNEMONIC_AND
		&& zydisInst->operand_count == 2
		&& operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
		)
	{
		if (operands[1].imm.is_signed)
		{
			if (operands[1].imm.value.s == -1)
			{
				inst.setIsNoOp(true);
			}
		}
		else
		{
			if (operands[1].imm.value.u == ZYAN_UINT64_MAX)
			{
				inst.setIsNoOp(true);
			}
		}
		
	}
}
