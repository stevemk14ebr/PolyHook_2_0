#include "headers/Detour/ILCallback.hpp"

uint64_t PLH::ILCallback::getJitFunc(const asmjit::FuncSignature sig, const PLH::ILCallback::tUserCallback callback, uint64_t* userTrampVar) {
	asmjit::CodeHolder code;                      
	code.init(asmjit::CodeInfo(asmjit::ArchInfo::kTypeHost));			
	
	// initialize function
	asmjit::X86Compiler cc(&code);            
	cc.addFunc(sig);              

	// to small to really need it
	cc.getFunc()->getFrameInfo().disablePreservedFP();
	
	// map argument slots to registers, following abi.
	std::vector<asmjit::Reg> argRegisters;
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		const uint8_t argType = sig.getArgs()[arg_idx];

		asmjit::Reg arg;
		if (isGeneralReg(argType)) {
			arg = cc.newInt32();
		} else if (isXmmReg(argType)) {
			arg = cc.newXmm();
		} else {
			ErrorLog::singleton().push("Parameters wider than 128bits not supported", ErrorLevel::SEV);
			return 0;
		}

		cc.setArg(arg_idx, arg);
		argRegisters.push_back(arg);
	}
  
	// setup the stack structure to hold arguments for user callback
	argsStack = cc.newStack((uint32_t)(sizeof(uint64_t) * sig.getArgCount()), 4);
	asmjit::X86Mem argsStackIdx(argsStack);               

	// assigns some register as index reg 
	asmjit::X86Gp i = cc.newIntPtr();

	// stackIdx <- stack[i].
	argsStackIdx.setIndex(i);                   

	// r/w are sizeof(uint64_t) width now
	argsStackIdx.setSize(sizeof(uint64_t));
	
	// set i = 0
	cc.mov(i, 0);  

	// mov from arguments registers into the stack structure
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		const uint8_t argType = sig.getArgs()[arg_idx];

		// have to cast back to explicit register types to gen right mov type
		if (isGeneralReg(argType)) {
			cc.mov(argsStackIdx, argRegisters.at(arg_idx).as<asmjit::X86Gp>());
		} else if(isXmmReg(argType)) {
			cc.vmovdqu(argsStackIdx, argRegisters.at(arg_idx).as<asmjit::X86Xmm>());
		} else {
			ErrorLog::singleton().push("Parameters wider than 128bits not supported", ErrorLevel::SEV);
			return 0;
		}

		// next structure slot (+= sizeof(uint64_t))
		cc.add(i, sizeof(uint64_t));
	}

	// get pointer to stack structure and pass it to the user callback
	asmjit::X86Gp argStruct = cc.newIntPtr("argStruct");
	cc.lea(argStruct, argsStack);

	// call to user provided function (use ABI of host compiler)
	auto call = cc.call(asmjit::imm_ptr((unsigned char*)callback), asmjit::FuncSignature1<void, const Parameters*>(asmjit::CallConv::kIdHost));
	call->setArg(0, argStruct);
	
	asmjit::X86Gp orig_ptr = cc.newUInt64();
	cc.mov(orig_ptr, (uint64_t)userTrampVar);
	cc.mov(orig_ptr, asmjit::x86::ptr(orig_ptr));

	// call trampoline, map input args same order they were passed to us
	auto orig_call = cc.call(orig_ptr, sig);
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		orig_call->setArg(arg_idx, argRegisters.at(arg_idx));
	}

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

bool PLH::ILCallback::isGeneralReg(const uint8_t typeId) const {
	switch (typeId) {
	case asmjit::TypeId::kI8:
	case asmjit::TypeId::kU8:
	case asmjit::TypeId::kI16:
	case asmjit::TypeId::kU16:
	case asmjit::TypeId::kI32:
	case asmjit::TypeId::kU32:
	case asmjit::TypeId::kI64:
	case asmjit::TypeId::kU64:
	case asmjit::TypeId::kIntPtr:
	case asmjit::TypeId::kUIntPtr:
		return true;
	default:
		return false;
	}
}


bool PLH::ILCallback::isXmmReg(const uint8_t typeId) const {
	switch (typeId) {
	case  asmjit::TypeId::kF32:
	case asmjit::TypeId::kF64:
	case asmjit::TypeId::kI32x4:
		return true;
	default:
		return false;
	}
}

PLH::ILCallback::~ILCallback() {
	m_mem.release((unsigned char*)m_callbackBuf);
}