#include "polyhook2/ZydisDisassembler.hpp"
#include "polyhook2/ErrorLog.hpp"

PLH::ZydisDisassembler::ZydisDisassembler(PLH::Mode mode) : m_decoder(new ZydisDecoder()), m_formatter(new ZydisFormatter()) {
	m_mode = mode;
	if (ZYAN_FAILED(ZydisDecoderInit(m_decoder,
		(mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
		(mode == PLH::Mode::x64) ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32)))
	{
		Log::log("Failed to initialize zydis decoder", ErrorLevel::SEV);
		return;
	}

	if (ZYAN_FAILED(ZydisFormatterInit(m_formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		Log::log("Failed to initialize zydis formatter", ErrorLevel::SEV);
		return;
	}

	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

PLH::ZydisDisassembler::~ZydisDisassembler() {
	if (m_decoder) {
		delete m_decoder;
		m_decoder = 0;
	}

	if (m_formatter) {
		delete m_formatter;
		m_formatter = 0;
	}
}

PLH::insts_t
PLH::ZydisDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End, const MemAccessor& accessor) {
	insts_t insVec;
	m_branchMap.clear();

	uint64_t size = End - start;
	assert(size > 0);
	if (size <= 0) {
		return insVec;
	}

	// copy potentially remote memory to local buffer
	uint8_t* buf = new uint8_t[(uint32_t)size];
	accessor.mem_copy((uint64_t)buf, firstInstruction, size);

	ZydisDecodedInstruction insInfo;
	uint64_t offset = 0;
	bool endHit = false;
	while(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(m_decoder, (char*)(buf + offset), (ZyanUSize)(size - offset), &insInfo)))
	{
		Instruction::Displacement displacement = {};
		displacement.Absolute = 0;

		uint64_t address = start + offset;
		
		std::string opstr;
		if(!getOpStr(&insInfo, address, &opstr))
			break;

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

		setDisplacementFields(inst, &insInfo);
		if (endHit && !isPadBytes(inst))
			break;

		insVec.push_back(inst);

		// searches instruction vector and updates references
		addToBranchMap(insVec, inst);
		if (isFuncEnd(inst))
			endHit = true;

		offset += insInfo.length;
	}
	delete[] buf;
	return insVec;
}

bool PLH::ZydisDisassembler::getOpStr(ZydisDecodedInstruction* pInstruction, uint64_t addr, std::string* pOpStrOut)
{
	char buffer[256];
	if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(m_formatter, pInstruction, buffer, sizeof(buffer), addr)))
	{
		// remove mnemonic + space (op str is just the right hand side)
		std::string wholeInstStr(buffer);
		*pOpStrOut = wholeInstStr.erase(0, wholeInstStr.find(' ') + 1);
		return true;
	}
	return false;
}

void PLH::ZydisDisassembler::setDisplacementFields(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst) const
{
	inst.setBranching(zydisInst->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE);
	inst.setCalling(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL);

	for(int i = 0; i < zydisInst->operand_count; i++)
	{
		const ZydisDecodedOperand* const operand = &zydisInst->operands[i];

		// skip implicit operands (r/w effects)
		if(operand->visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN)
			continue;

		switch (operand->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
        case ZYDIS_OPERAND_TYPE_UNUSED:
       
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
			// Relative to RIP/EIP
		
		{
			if (zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setDisplacementOffset(zydisInst->raw.disp.offset);
				inst.setRelativeDisplacement(operand->mem.disp.value);
			}

			if ((zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x15) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15)
				) {

				// is displacement set earlier already?
				if (!inst.hasDisplacement()) {
					// displacement is absolute on x86 mode
					inst.setDisplacementOffset(zydisInst->raw.disp.offset);
					inst.setAbsoluteDisplacement(zydisInst->raw.disp.value);
				}
				inst.setIndirect(true);
			}
		}
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
			
            break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			// is displacement set earlier already?
			if(!inst.hasDisplacement() && zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setDisplacementOffset(zydisInst->raw.imm->offset);
				inst.setRelativeDisplacement(zydisInst->raw.imm->value.s);
				return;
			} else {
                inst.setImmediateOffset(zydisInst->raw.imm->offset);
			}
            break;
		}
	}
}
