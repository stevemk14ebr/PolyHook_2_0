#include "headers/Detour/ILCallback.hpp"

uint64_t ILCallback::getJitFunc(const PLH::CallConv conv) {
	asmjit::CodeHolder code;                      
	code.init(asmjit::CodeInfo(asmjit::ArchInfo::kTypeHost));			

	unsigned char* regBuf[12 * 8];
	memset(regBuf, 0, sizeof(regBuf));

	if (conv == PLH::CallConv::MS_x64) {
		auto arg1 = getRegForArg(0, conv);

		asmjit::X86Assembler a(&code);
		a.mov(asmjit::x86::ptr((uint64_t)regBuf), arg1.as<asmjit::X86Gp>());
		a.ret();

		// worst case, overestimates for if trampolines needed
		size_t size = code.getCodeSize();

		// Allocate a virtual memory (executable).
		m_callbackBuf = (uint64_t)m_mem.alloc(size);
		if (!m_callbackBuf)
			return 0;

		// Relocate & store the output in p
		code.relocate((unsigned char*)m_callbackBuf);
	}
	return 0;
}

ILCallback::~ILCallback() {
	m_mem.release((unsigned char*)m_callbackBuf);
}

asmjit::Operand ILCallback::getRegForArg(const uint8_t idx, const PLH::CallConv conv) const {
	switch (conv) {
	case PLH::CallConv::MS_x64:
		switch (idx) {
		case 0:
			return asmjit::x86::rcx;
		case 1:
			return asmjit::x86::rdx;
		case 2:
			return asmjit::x86::r8;
		case 3:
			return asmjit::x86::r9;
		default:
			if (idx >= 4) {
				// 5th
				const uint8_t slot = idx - 4;
				return asmjit::x86::ptr(asmjit::x86::rsp, 32 + 8 * slot);
			}
		}
		break;
	default:
		break;
	}
	return asmjit::Operand();
}