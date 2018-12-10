#include "headers/Detour/ILCallback.hpp"

asmjit::CallConv::Id PLH::ILCallback::getCallConv(const std::string& conv) {
	if (conv == "cdecl") {
		return asmjit::CallConv::kIdHostCDecl;
	}else if (conv == "stdcall") {
		return asmjit::CallConv::kIdHostStdCall;
	}else if (conv == "fastcall") {
		return asmjit::CallConv::kIdHostFastCall;
	} 
	return asmjit::CallConv::kIdHost;
}

#define TYPEID_MATCH_STR_IF(var, T) if (var == #T) { return asmjit::TypeIdOf<T>::kTypeId; }
#define TYPEID_MATCH_STR_ELSEIF(var, T)  else if (var == #T) { return asmjit::TypeIdOf<T>::kTypeId; }

uint8_t PLH::ILCallback::getTypeId(const std::string& type) {
	if (type.find("*") != std::string::npos) {
		return asmjit::TypeId::kUIntPtr;
	}

	TYPEID_MATCH_STR_IF(type, signed char)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned char)
	TYPEID_MATCH_STR_ELSEIF(type, short)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned short)
	TYPEID_MATCH_STR_ELSEIF(type, int)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned int)
	TYPEID_MATCH_STR_ELSEIF(type, long)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned long)
	TYPEID_MATCH_STR_ELSEIF(type, __int64)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned __int64)
	TYPEID_MATCH_STR_ELSEIF(type, long long)
	TYPEID_MATCH_STR_ELSEIF(type, unsigned long long)
	TYPEID_MATCH_STR_ELSEIF(type, char)
	TYPEID_MATCH_STR_ELSEIF(type, char16_t)
	TYPEID_MATCH_STR_ELSEIF(type, char32_t)
	TYPEID_MATCH_STR_ELSEIF(type, wchar_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint8_t)
	TYPEID_MATCH_STR_ELSEIF(type, int8_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint16_t)
	TYPEID_MATCH_STR_ELSEIF(type, int16_t)
	TYPEID_MATCH_STR_ELSEIF(type, int32_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint32_t)
	TYPEID_MATCH_STR_ELSEIF(type, uint64_t)
	TYPEID_MATCH_STR_ELSEIF(type, int64_t)
	TYPEID_MATCH_STR_ELSEIF(type, float)
	TYPEID_MATCH_STR_ELSEIF(type, double)
	TYPEID_MATCH_STR_ELSEIF(type, bool)
	TYPEID_MATCH_STR_ELSEIF(type, void)
	else if (type == "intptr_t") {
		return asmjit::TypeId::kIntPtr;
	}else if (type == "uintptr_t") {
		return asmjit::TypeId::kUIntPtr;
	} 

	return asmjit::TypeId::kVoid;
}

uint64_t PLH::ILCallback::getJitFunc(const asmjit::FuncSignature& sig, const PLH::ILCallback::tUserCallback callback, const uint64_t retAddr /* = 0 */) {
	/*AsmJit is smart enough to track register allocations and will forward
	  the proper registers the right values and fixup any it dirtied earlier.
	  This can only be done if it knows the signature, and ABI, so we give it 
	  them. It also only does this mapping for calls, so we need to generate 
	  calls on our boundaries of transfers when we want argument order correct
	  (ABI stuff is managed for us when calling C code within this project via host mode).
	*/
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
			ErrorLog::singleton().push("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		cc.setArg(arg_idx, arg);
		argRegisters.push_back(arg);
	}
  
	// setup the stack structure to hold arguments for user callback
	argsStack = cc.newStack((uint32_t)(sizeof(uint64_t) * sig.getArgCount()), 4);
	asmjit::X86Mem argsStackIdx(argsStack);               

	// assigns some register as index reg 
	asmjit::X86Gp i = cc.newUIntPtr();

	// stackIdx <- stack[i].
	argsStackIdx.setIndex(i);                   

	// r/w are sizeof(uint64_t) width now
	argsStackIdx.setSize(sizeof(uint64_t));
	
	// set i = 0
	cc.mov(i, 0);  
	UNREFERENCED_PARAMETER(callback);
	//// mov from arguments registers into the stack structure
	for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
		const uint8_t argType = sig.getArgs()[arg_idx];

		// have to cast back to explicit register types to gen right mov type
		if (isGeneralReg(argType)) {
			cc.mov(argsStackIdx, argRegisters.at(arg_idx).as<asmjit::X86Gp>());
		} else if(isXmmReg(argType)) {
			cc.movq(argsStackIdx, argRegisters.at(arg_idx).as<asmjit::X86Xmm>());
		} else {
			ErrorLog::singleton().push("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		// next structure slot (+= sizeof(uint64_t))
		cc.add(i, sizeof(uint64_t));
	}

	// get pointer to stack structure and pass it to the user callback
	asmjit::X86Gp argStruct = cc.newUIntPtr("argStruct");
	cc.lea(argStruct, argsStack);

	// fill reg to pass struct arg count to callback
	asmjit::X86Gp argCountParam = cc.newU8();
	cc.mov(argCountParam, (uint8_t)sig.getArgCount());

	// call to user provided function (use ABI of host compiler)
	auto call = cc.call(asmjit::imm_ptr((unsigned char*)callback), asmjit::FuncSignature2<void, Parameters*, uint8_t>(asmjit::CallConv::kIdHost));
	call->setArg(0, argStruct);
	call->setArg(1, argCountParam);
	
	// deref the trampoline ptr (must live longer)
	asmjit::X86Gp orig_ptr = cc.newUIntPtr();;
	cc.mov(orig_ptr, (uintptr_t)getTrampolineHolder());
	cc.mov(orig_ptr, asmjit::x86::ptr(orig_ptr));

	/*-- OPTIONALLY SPOOF RET ADDR --
	If the retAddr param is != 0 then we transfer via a push of dest addr, ret addr, and jmp.
	Other wise we just call. Potentially useful for defensive binaries.
	*/
	/*unsigned char* retBufTmp = (unsigned char*)m_mem.getBlock(10);
	*(unsigned char*)retBufTmp = 0xC3;*/
	
	uint64_t retAddrReal = retAddr;
	//retAddrReal = (uint64_t)retBufTmp;
	if (retAddrReal == 0) {
		/* call trampoline, map input args same order they were passed to us.*/
		auto orig_call = cc.call(orig_ptr, sig);
		for (uint8_t arg_idx = 0; arg_idx < sig.getArgCount(); arg_idx++) {
			orig_call->setArg(arg_idx, argRegisters.at(arg_idx));
		}

		cc.endFunc();
		cc.finalize();
	} else {
		//asmjit::Label ret_jit_stub = cc.newLabel();
		//asmjit::X86Gp tmpReg = cc.newUIntPtr();
		//cc.lea(tmpReg, asmjit::x86::ptr(ret_jit_stub));
		//
		//cc.push(tmpReg); // push ret
		//cc.push((uintptr_t)retAddrReal); // push &ret_inst
		//cc.jmp(orig_ptr); // jmp orig
		//cc.bind(ret_jit_stub); // ret_inst:
		//cc.endFunc(); // omit prolog cleanup
		//cc.finalize();
	}
	
	// end function

	
	// worst case, overestimates for case trampolines needed
	size_t size = code.getCodeSize();

	// Allocate a virtual memory (executable).
	m_callbackBuf = (uint64_t)m_mem.getBlock(size);
	if (!m_callbackBuf) {
		__debugbreak();
		return 0;
	}

	// Relocate & store the output in p
	code.relocate((unsigned char*)m_callbackBuf, m_callbackBuf);
	return m_callbackBuf;
}

uint64_t PLH::ILCallback::getJitFunc(const std::string& retType, const std::vector<std::string>& paramTypes, const tUserCallback callback, std::string callConv/* = ""*/, const uint64_t retAddr /* = 0 */) {
	asmjit::FuncSignature sig;
	std::vector<uint8_t> args;
	for (const std::string& s : paramTypes) {
		args.push_back(getTypeId(s));
	}
	sig.init(getCallConv(callConv), getTypeId(retType), args.data(), (uint32_t)args.size());
	return getJitFunc(sig, callback, retAddr);
}

uint64_t* PLH::ILCallback::getTrampolineHolder() {
	return &m_trampolinePtr;
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
		return true;
	default:
		return false;
	}
}

PLH::ILCallback::ILCallback() : m_mem(0, 0) {
	m_callbackBuf = 0;
	m_trampolinePtr = 0;
}

PLH::ILCallback::~ILCallback() {
	
}