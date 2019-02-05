#include "headers/ZydisDisassembler.hpp"

PLH::insts_t
PLH::ZydisDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End) {
	insts_t insVec;
	m_branchMap.clear();

	ZydisDecodedInstruction insInfo;
	uint64_t offset = 0;
	while(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, (char*)(firstInstruction + offset), (ZyanUSize)(End - start - offset), &insInfo)))
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

void PLH::ZydisDisassembler::setDisplacementFields(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst) const
{
	auto cat = zydisInst->meta.category;
	const bool branches = cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR || cat == ZYDIS_CATEGORY_CALL;
	assert(branches == (zydisInst->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && cat != ZYDIS_CATEGORY_RET)); // decide if use branch_type or category for this signal (ignore ret)
	inst.setBranching(branches);

	for(int i = 0; i < zydisInst->operand_count; i++)
	{
		const ZydisDecodedOperand* const operand = &zydisInst->operands[i];

		switch (operand->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
       
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
			// Relative to RIP/EIP
			if(zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setDisplacementOffset(zydisInst->raw.disp.offset);
				inst.setRelativeDisplacement(operand->mem.disp.value);
			}
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
			
            break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if(zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
			{
				inst.setRelativeDisplacement(zydisInst->raw.imm->value.s);
			}
            break;
		}
	}
}
