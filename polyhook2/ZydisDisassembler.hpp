#ifndef POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP
#define POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP

#include <memory>
#include <string>

#include <Zydis/Zydis.h>
#include <Zycore/Status.h>

#include "polyhook2/ADisassembler.hpp"

#define unreferenced(P) (P)

namespace PLH {
class ZydisDisassembler : public ADisassembler {
public:
	ZydisDisassembler(PLH::Mode mode);

	virtual ~ZydisDisassembler();

	virtual std::vector<PLH::Instruction>
		disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end, const MemAccessor& accessor) override;
private:

	bool getOpStr(ZydisDecodedInstruction* pInstruction, uint64_t addr, std::string* pOpStrOut);

	void setDisplacementFields(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst) const;

	ZydisDecoder* m_decoder;
	ZydisFormatter* m_formatter;
};
}

#endif