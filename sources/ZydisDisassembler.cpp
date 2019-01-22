#include "headers/ZydisDisassembler.hpp"

PLH::insts_t
PLH::ZydisDisassembler::disassemble(uint64_t firstInstruction, uint64_t start, uint64_t End) {
	insts_t insVec;
	m_branchMap.clear();

	ZydisDecodedInstruction insInfo;
	uint64_t offset = 0;
	while(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, (char*)(firstInstruction + offset), (ZyanUSize)(End - start), &insInfo)))
	{
		Instruction::Displacement displacement = {};
		displacement.Absolute = 0;

		Instruction inst(start + offset,
						 displacement,
						 0,
						 false,
						 (uint8_t*)((char*)firstInstruction + offset),
						 insInfo.length,
						 "mn",
						 "op",
						 m_mode);
		insVec.push_back(inst);
		offset += insInfo.length;
	}
	return insVec;
}