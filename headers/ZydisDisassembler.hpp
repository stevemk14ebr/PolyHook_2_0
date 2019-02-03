#ifndef POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP
#define POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP

#include <string>

#include <Zydis/Zydis.h>

#include "headers/ADisassembler.hpp"
#include "Zycore/Status.h"

namespace PLH {
class ZydisDisassembler : public ADisassembler {
public:
	ZydisDisassembler(PLH::Mode mode) : ADisassembler(mode) {
		if(ZYAN_FAILED(ZydisDecoderInit(&m_decoder, (mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32)))
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
	

	bool getTokenMnemonic(ZydisDecodedInstruction* pInstruction, uint64_t addr, std::string* pMnemonicOut)
	{
		char buffer[256];
		const ZydisFormatterToken* token;
        for(ZyanStatus status = ZydisFormatterTokenizeInstruction(&m_formatter, pInstruction, &buffer[0], sizeof(buffer), addr, &token); 
			ZYAN_SUCCESS(status) && token; status = ZydisFormatterTokenNext(&token))
        {
			char* token_value;
			ZydisTokenType token_type;
			ZydisFormatterTokenGetValue(token, &token_type, &token_value);
			if(token_type != ZYDIS_TOKEN_MNEMONIC)
				continue;

			*pMnemonicOut = std::string(token_value);
			return true;
        }
		*pMnemonicOut = "";
		return false;
	}

	bool getOpStr(ZydisDecodedInstruction* pInstruction, uint64_t addr, std::string* pOpStrOut)
	{
		char buffer[256];
        if(ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&m_formatter, pInstruction, buffer, sizeof(buffer), addr)))
        {
	        *pOpStrOut = std::string(buffer);
			return true;
        }
		return false;
	}

	ZydisDecoder m_decoder;
	ZydisFormatter m_formatter;
};
}

#endif