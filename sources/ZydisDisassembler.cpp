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

		std::string mnemonic;
		if(!getTokenMnemonic(&insInfo, address, &mnemonic))
			break;

		std::string opstr;
		if(!getOpStr(&insInfo, address, &opstr))
			break;

		Instruction inst(address,
						 displacement,
						 0,
						 false,
						 (uint8_t*)((char*)firstInstruction + offset),
						 insInfo.length,
						 mnemonic,
						 opstr,
						 m_mode);
		insVec.push_back(inst);
		offset += insInfo.length;
	}
	return insVec;
}