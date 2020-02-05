#ifndef POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP
#define POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP

#include <string>

#include <Zydis/Zydis.h>

#include "polyhook2/ADisassembler.hpp"
#include "Zycore/Status.h"

#define unreferenced(P) (P)

namespace PLH {
class ZydisDisassembler : public ADisassembler {
public:
	ZydisDisassembler(PLH::Mode mode) : ADisassembler(mode) {
		if(ZYAN_FAILED(ZydisDecoderInit(&m_decoder,
			(mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
			(mode == PLH::Mode::x64) ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32)))
		{
			ErrorLog::singleton().push("Failed to initialize zydis decoder", ErrorLevel::SEV);
			return;
		}

	    if(ZYAN_FAILED(ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		{
			ErrorLog::singleton().push("Failed to initialize zydis formatter", ErrorLevel::SEV);
			return;
		}

	    ZydisFormatterSetProperty(&m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	    ZydisFormatterSetProperty(&m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	}

	virtual ~ZydisDisassembler() = default;

	virtual std::vector<PLH::Instruction>
		disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) override;
private:

	bool getOpStr(ZydisDecodedInstruction* pInstruction, uint64_t addr, std::string* pOpStrOut)
	{
		char buffer[256];
        if(ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&m_formatter, pInstruction, buffer, sizeof(buffer), addr)))
        {
			// remove mnemonic + space (op str is just the right hand side)
			std::string wholeInstStr(buffer);
	        *pOpStrOut = wholeInstStr.erase(0, wholeInstStr.find(' ') + 1);
			return true;
        }
		return false;
	}

	void setDisplacementFields(PLH::Instruction& inst, const ZydisDecodedInstruction* zydisInst) const;

	ZydisDecoder m_decoder;
	ZydisFormatter m_formatter;
};
}

#endif