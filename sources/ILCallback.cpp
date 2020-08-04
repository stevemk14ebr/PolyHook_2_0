#include "polyhook2/Detour/ILCallback.hpp"

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

#define TYPEID_MATCH_STR_IF(var, T) if (var == #T) { return asmjit::Type::IdOfT<T>::kTypeId; }
#define TYPEID_MATCH_STR_ELSEIF(var, T)  else if (var == #T) { return asmjit::Type::IdOfT<T>::kTypeId; }

uint8_t PLH::ILCallback::getTypeId(const std::string& type) {
	if (type.find("*") != std::string::npos) {
		return asmjit::Type::kIdUIntPtr;
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
		return asmjit::Type::kIdIntPtr;
	}else if (type == "uintptr_t") {
		return asmjit::Type::kIdUIntPtr;
	} 

	return asmjit::Type::kIdVoid;
}

uint64_t PLH::ILCallback::getJitFunc(const asmjit::FuncSignature& sig, const asmjit::Environment::Arch arch, const PLH::ILCallback::tUserCallback callback) {;
	/*AsmJit is smart enough to track register allocations and will forward
	  the proper registers the right values and fixup any it dirtied earlier.
	  This can only be done if it knows the signature, and ABI, so we give it 
	  them. It also only does this mapping for calls, so we need to generate 
	  calls on our boundaries of transfers when we want argument order correct
	  (ABI stuff is managed for us when calling C code within this project via host mode).
	  It also does stack operations for us including alignment, shadow space, and
	  arguments, everything really. Manual stack push/pop is not supported using
	  the AsmJit compiler, so we must create those nodes, and insert them into
	  the Node list manually to not corrupt the compiler's tracking of things.

	  Inside the compiler, before endFunc only virtual registers may be used. Any
	  concrete physical registers will not have their liveness tracked, so will
	  be spoiled and must be manually marked dirty. After endFunc ONLY concrete
	  physical registers may be inserted as nodes.
	*/
	asmjit::CodeHolder code;        
	auto env = asmjit::hostEnvironment();
	env.setArch(arch);
	code.init(env);
	
	// initialize function
	asmjit::x86::Compiler cc(&code);            
	asmjit::FuncNode* func = cc.addFunc(sig);              

	asmjit::StringLogger log;
	uint32_t kFormatFlags = asmjit::FormatOptions::kFlagMachineCode | asmjit::FormatOptions::kFlagExplainImms | asmjit::FormatOptions::kFlagRegCasts 
		| asmjit::FormatOptions::kFlagAnnotations | asmjit::FormatOptions::kFlagDebugPasses | asmjit::FormatOptions::kFlagDebugRA
		| asmjit::FormatOptions::kFlagHexImms | asmjit::FormatOptions::kFlagHexOffsets | asmjit::FormatOptions::kFlagPositions;
	
	log.addFlags(kFormatFlags);
	code.setLogger(&log);
	
	// too small to really need it
	func->frame().resetPreservedFP();
	
	// map argument slots to registers, following abi.
	std::vector<asmjit::x86::Reg> argRegisters;
	for (uint8_t argIdx = 0; argIdx < sig.argCount(); argIdx++) {
		const uint8_t argType = sig.args()[argIdx];

		asmjit::x86::Reg arg;
		if (isGeneralReg(argType)) {
			arg = cc.newUIntPtr();
		} else if (isXmmReg(argType)) {
			arg = cc.newXmm();
		} else {
			Log::log("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		cc.setArg(argIdx, arg);
		argRegisters.push_back(arg);
	}
  
	// setup the stack structure to hold arguments for user callback
	uint32_t stackSize = (uint32_t)(sizeof(uint64_t) * sig.argCount());
	argsStack = cc.newStack(stackSize, 16);
	asmjit::x86::Mem argsStackIdx(argsStack);               

	// assigns some register as index reg 
	asmjit::x86::Gp i = cc.newUIntPtr();

	// stackIdx <- stack[i].
	argsStackIdx.setIndex(i);                   

	// r/w are sizeof(uint64_t) width now
	argsStackIdx.setSize(sizeof(uint64_t));
	
	// set i = 0
	cc.mov(i, 0);
	//// mov from arguments registers into the stack structure
	for (uint8_t argIdx = 0; argIdx < sig.argCount(); argIdx++) {
		const uint8_t argType = sig.args()[argIdx];

		// have to cast back to explicit register types to gen right mov type
		if (isGeneralReg(argType)) {
			cc.mov(argsStackIdx, argRegisters.at(argIdx).as<asmjit::x86::Gp>());
		} else if(isXmmReg(argType)) {
			cc.movq(argsStackIdx, argRegisters.at(argIdx).as<asmjit::x86::Xmm>());
		} else {
			Log::log("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		// next structure slot (+= sizeof(uint64_t))
		cc.add(i, sizeof(uint64_t));
	}

	// get pointer to stack structure and pass it to the user callback
	asmjit::x86::Gp argStruct = cc.newUIntPtr("argStruct");
	cc.lea(argStruct, argsStack);

	// fill reg to pass struct arg count to callback
	asmjit::x86::Gp argCountParam = cc.newU8();
	cc.mov(argCountParam, (uint8_t)sig.argCount());

	// create buffer for ret val
	asmjit::x86::Mem retStack = cc.newStack(sizeof(uint64_t), 16);
	asmjit::x86::Gp retStruct = cc.newUIntPtr("retStruct");
	cc.lea(retStruct, retStack);

	asmjit::InvokeNode* invokeNode;
	cc.invoke(&invokeNode,
		(uint64_t)callback,
		asmjit::FuncSignatureT<void, Parameters*, uint8_t, ReturnValue*>()
	);

	// call to user provided function (use ABI of host compiler)
	invokeNode->setArg(0, argStruct);
	invokeNode->setArg(1, argCountParam);
	invokeNode->setArg(2, retStruct);

	// mov from arguments stack structure into regs
	cc.mov(i, 0); // reset idx
	for (uint8_t arg_idx = 0; arg_idx < sig.argCount(); arg_idx++) {
		const uint8_t argType = sig.args()[arg_idx];

		if (isGeneralReg(argType)) {
			cc.mov(argRegisters.at(arg_idx).as<asmjit::x86::Gp>(), argsStackIdx);
		}else if (isXmmReg(argType)) {
			cc.movq(argRegisters.at(arg_idx).as<asmjit::x86::Xmm>(), argsStackIdx);
		}else {
			Log::log("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		// next structure slot (+= sizeof(uint64_t))
		cc.add(i, sizeof(uint64_t));
	}

	// deref the trampoline ptr (holder must live longer, must be concrete reg since push later)
	asmjit::x86::Gp origPtr = cc.zbx();
	cc.mov(origPtr, (uintptr_t)getTrampolineHolder());
	cc.mov(origPtr, asmjit::x86::ptr(origPtr));

	asmjit::InvokeNode* origInvokeNode;
	cc.invoke(&origInvokeNode, origPtr, sig);
	for (uint8_t argIdx = 0; argIdx < sig.argCount(); argIdx++) {
		origInvokeNode->setArg(argIdx, argRegisters.at(argIdx));
	}
	
	if (sig.hasRet()) {
		asmjit::x86::Mem retStackIdx(retStack);
		retStackIdx.setSize(sizeof(uint64_t));
		if (isGeneralReg((uint8_t)sig.ret())) {
			asmjit::x86::Gp tmp2 = cc.newUIntPtr();
			cc.mov(tmp2, retStackIdx);
			cc.ret(tmp2);
		} else {
			asmjit::x86::Xmm tmp2 = cc.newXmm();
			cc.movq(tmp2, retStackIdx);
			cc.ret(tmp2);
		}
	}

	cc.func()->frame().addDirtyRegs(origPtr);
	
	cc.endFunc();

	// write to buffer
	cc.finalize();

	// worst case, overestimates for case trampolines needed
	code.flatten();
	size_t size = code.codeSize();

	// Allocate a virtual memory (executable).
	m_callbackBuf = (uint64_t)m_mem.getBlock(size);
	if (!m_callbackBuf) {
		__debugbreak();
		return 0;
	}

	// if multiple sections, resolve linkage (1 atm)
	if (code.hasUnresolvedLinks()) {
		code.resolveUnresolvedLinks();
	}

	 // Relocate to the base-address of the allocated memory.
	code.relocateToBase(m_callbackBuf);
	code.copyFlattenedData((unsigned char*)m_callbackBuf, size);

	Log::log("JIT Stub:\n" + std::string(log.data()), ErrorLevel::INFO);
	return m_callbackBuf;
}

uint64_t PLH::ILCallback::getJitFunc(const std::string& retType, const std::vector<std::string>& paramTypes, const asmjit::Environment::Arch arch, const tUserCallback callback, std::string callConv/* = ""*/) {
	asmjit::FuncSignature sig = {};
	std::vector<uint8_t> args;
	for (const std::string& s : paramTypes) {
		args.push_back(getTypeId(s));
	}
	sig.init(getCallConv(callConv),asmjit::FuncSignature::kNoVarArgs, getTypeId(retType), args.data(), (uint32_t)args.size());
	return getJitFunc(sig, arch, callback);
}

uint64_t* PLH::ILCallback::getTrampolineHolder() {
	return &m_trampolinePtr;
}

bool PLH::ILCallback::isGeneralReg(const uint8_t typeId) const {
	switch (typeId) {
	case asmjit::Type::kIdI8:
	case asmjit::Type::kIdU8:
	case asmjit::Type::kIdI16:
	case asmjit::Type::kIdU16:
	case asmjit::Type::kIdI32:
	case asmjit::Type::kIdU32:
	case asmjit::Type::kIdI64:
	case asmjit::Type::kIdU64:
	case asmjit::Type::kIdIntPtr:
	case asmjit::Type::kIdUIntPtr:
		return true;
	default:
		return false;
	}
}

bool PLH::ILCallback::isXmmReg(const uint8_t typeId) const {
	switch (typeId) {
	case  asmjit::Type::kIdF32:
	case asmjit::Type::kIdF64:
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
