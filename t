[1mdiff --git a/headers/Detour/ILCallback.hpp b/headers/Detour/ILCallback.hpp[m
[1mindex 469e940..4f490ff 100644[m
[1m--- a/headers/Detour/ILCallback.hpp[m
[1m+++ b/headers/Detour/ILCallback.hpp[m
[36m@@ -4,11 +4,14 @@[m
 #pragma warning( pop )[m
 [m
 #include "headers/Enums.hpp"[m
[32m+[m
[32m+[m[32m#include <vector>[m
 class ILCallback {[m
 public:[m
[32m+[m	[32mtypedef void(*tUserCallback)();[m
 	ILCallback() = default;[m
 	~ILCallback();[m
[31m-	uint64_t getJitFunc(const PLH::CallConv conv);[m
[32m+[m	[32muint64_t getJitFunc(const PLH::CallConv conv, tUserCallback callback);[m
 [m
 	/* all mem calculations assume rsp/rbp are values BEFORE execution but AFTER call,[m
 	i.e about to exec prolog. */[m
[36m@@ -17,4 +20,5 @@[m [mprivate:[m
 	// asmjit's memory manager, manages JIT'd code[m
 	asmjit::VMemMgr m_mem; [m
 	uint64_t m_callbackBuf;[m
[32m+[m	[32muint64_t m_returnValBuf;[m[41m [m
 };[m
\ No newline at end of file[m
[1mdiff --git a/sources/ILCallback.cpp b/sources/ILCallback.cpp[m
[1mindex 6332361..9fed60f 100644[m
[1m--- a/sources/ILCallback.cpp[m
[1m+++ b/sources/ILCallback.cpp[m
[36m@@ -3,28 +3,30 @@[m
 uint64_t ILCallback::getJitFunc(const PLH::CallConv conv) {[m
 	asmjit::CodeHolder code;                      [m
 	code.init(asmjit::CodeInfo(asmjit::ArchInfo::kTypeHost));			[m
[31m-[m
[31m-	unsigned char* regBuf[12 * 8];[m
[31m-	memset(regBuf, 0, sizeof(regBuf));[m
[31m-[m
[31m-	if (conv == PLH::CallConv::MS_x64) {[m
[31m-		auto arg1 = getRegForArg(0, conv);[m
[31m-[m
[31m-		asmjit::X86Assembler a(&code);[m
[31m-		a.mov(asmjit::x86::ptr((uint64_t)regBuf), arg1.as<asmjit::X86Gp>());[m
[31m-		a.ret();[m
[31m-[m
[31m-		// worst case, overestimates for if trampolines needed[m
[31m-		size_t size = code.getCodeSize();[m
[31m-[m
[31m-		// Allocate a virtual memory (executable).[m
[31m-		m_callbackBuf = (uint64_t)m_mem.alloc(size);[m
[31m-		if (!m_callbackBuf)[m
[31m-			return 0;[m
[31m-[m
[31m-		// Relocate & store the output in p[m
[31m-		code.relocate((unsigned char*)m_callbackBuf);[m
[31m-	}[m
[32m+[m[41m	[m
[32m+[m	[32m// void func(int)[m
[32m+[m	[32masmjit::FuncSignature sig;[m
[32m+[m	[32mstd::vector<uint8_t> args = { asmjit::TypeIdOf<int>::kTypeId };[m
[32m+[m	[32msig.init(asmjit::CallConv::kIdHost, asmjit::TypeIdOf<void>::kTypeId, args.data(), args.size());[m
[32m+[m
[32m+[m	[32masmjit::X86Compiler cc(&code);[m[41m            [m
[32m+[m	[32mcc.addFunc(sig);[m[41m                      [m
[32m+[m
[32m+[m	[32masmjit::X86Gp a = cc.newInt32("a");[m
[32m+[m	[32mcc.setArg(0, a);[m[41m               [m
[32m+[m	[32mcc.endFunc();[m[41m                     [m
[32m+[m	[32mcc.finalize();[m
[32m+[m
[32m+[m	[32m// worst case, overestimates for if trampolines needed[m
[32m+[m	[32msize_t size = code.getCodeSize();[m
[32m+[m
[32m+[m	[32m// Allocate a virtual memory (executable).[m
[32m+[m	[32mm_callbackBuf = (uint64_t)m_mem.alloc(size);[m
[32m+[m	[32mif (!m_callbackBuf)[m
[32m+[m		[32mreturn 0;[m
[32m+[m
[32m+[m	[32m// Relocate & store the output in p[m
[32m+[m	[32mcode.relocate((unsigned char*)m_callbackBuf);[m
 	return 0;[m
 }[m
 [m
