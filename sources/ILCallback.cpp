#include "headers/Detour/ILCallback.hpp"

uint64_t PLH::ILCallback::getJitFunc(const asmjit::FuncSignature sig, const PLH::ILCallback::tUserCallback callback) {
	asmjit::CodeHolder code;                      
	code.init(asmjit::CodeInfo(asmjit::ArchInfo::kTypeHost));			
	
	// initialize function
	asmjit::X86Compiler cc(&code);            
	cc.addFunc(sig);                      
	
	// map register slots for function to types
	std::vector<asmjit::X86Gp> argRegisters;
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		asmjit::X86Gp arg = cc.newInt32();
		cc.setArg(0, arg);
		argRegisters.push_back(arg);
	}
  
	argsStack = cc.newStack((uint32_t)(sizeof(uint64_t) * sig.getArgCount()), 4);
	asmjit::X86Mem argsStackIdx(argsStack);               
	asmjit::X86Gp i = cc.newIntPtr("i");
	argsStackIdx.setIndex(i);                   // stackIdx <- stack[i].
	argsStackIdx.setSize(8);                    // stackIdx <- sizeof(uint64_t) stack[i]
	
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		cc.mov(argsStackIdx, argRegisters.at(arg_idx));
		cc.inc(i);
	}

	asmjit::X86Gp argStruct = cc.newIntPtr("argStruct");
	cc.lea(argStruct, argsStack);
	// call to user provided function (use ABI of host compiler)
	auto call = cc.call(asmjit::imm_ptr((unsigned char*)callback), asmjit::FuncSignature1<void, const Parameters*>(asmjit::CallConv::kIdHost));
	call->setArg(0, argStruct);

	// end function
	cc.endFunc();                     
	cc.finalize();

	// worst case, overestimates for case trampolines needed
	size_t size = code.getCodeSize();

	// Allocate a virtual memory (executable).
	m_callbackBuf = (uint64_t)m_mem.alloc(size);
	if (!m_callbackBuf) {
		__debugbreak();
		return 0;
	}

	// Relocate & store the output in p
	code.relocate((unsigned char*)m_callbackBuf);
	return m_callbackBuf;
}

PLH::ILCallback::~ILCallback() {
	m_mem.release((unsigned char*)m_callbackBuf);
}