#ifndef POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP
#define POLYHOOK_2_0_ZYDISDISASSEMBLER_HPP

#include <Zydis/Zydis.h>

#include "headers/ADisassembler.hpp"
#include "Zycore/Status.h"

namespace PLH {

class ZydisDisassembler : public ADisassembler {
public:
	ZydisDisassembler(PLH::Mode mode) : ADisassembler(mode) {
		if(ZYAN_FAILED(ZydisDecoderInit(&m_decoder, (mode == PLH::Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_64)))
			ErrorLog::singleton().push("Failed to initialize zydis decoder", ErrorLevel::SEV);
	}

	virtual ~ZydisDisassembler() {
	
	}

	virtual std::vector<PLH::Instruction>
		disassemble(uint64_t firstInstruction, uint64_t start, uint64_t end) override;
private:
	ZydisDecoder m_decoder;
};
}

#endif