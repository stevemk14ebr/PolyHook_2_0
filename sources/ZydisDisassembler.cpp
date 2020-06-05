#include "polyhook2/ZydisDisassembler.hpp"


PLH::ZydisDisassembler::ZydisDisassembler(PLH::Mode mode) : ADisassembler(mode), m_decoder(new ZydisDecoder()), m_formatter(new ZydisFormatter()) {
	
	if (ZYAN_FAILED(ZydisDecoderInit(m_decoder,
		(mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
		(mode == PLH::Mode::x64) ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32)))
	{
		ErrorLog::singleton().push("Failed to initialize zydis decoder", ErrorLevel::SEV);
		return;
	}

	if (ZYAN_FAILED(ZydisFormatterInit(m_formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		ErrorLog::singleton().push("Failed to initialize zydis formatter", ErrorLevel::SEV);
		return;
	}

	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

PLH::ZydisDisassembler::~ZydisDisassembler() {
	delete m_decoder;
	delete m_formatter;
}

PLH::insts_t
PLH::ZydisDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End) {
	insts_t insVec;
	m_branchMap.clear();

	ZydisDecodedInstruction insInfo;
	uint64_t offset = 0;
	while(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(m_decoder, (char*)(firstInstruction + offset), (ZyanUSize)(End - start - offset), &insInfo)))
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
						 (uint8_t*)((unsigned char*)firstInstruction + offset),
						 insInfo.length,
						 ZydisMnemonicGetString(insInfo.mnemonic),
						 opstr,
						 m_mode);

		setDisplacementFields(inst, &insInfo);
		insVec.push_back(inst);

		// searches instruction vector and updates references
		addToBranchMap(insVec, inst);

		offset += insInfo.length;
	}
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
			bool set = false;
			if (zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setDisplacementOffset(zydisInst->raw.disp.offset);
				inst.setRelativeDisplacement(operand->mem.disp.value);
				set = true;
			}

			if ((zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x15) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15) ||
				(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15)
				) {

				if (!set) {
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
			if(zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setDisplacementOffset(zydisInst->raw.imm->offset);
				inst.setRelativeDisplacement(zydisInst->raw.imm->value.s);
				return;
			}
            break;
		}
	}
}
