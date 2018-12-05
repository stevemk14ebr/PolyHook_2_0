#pragma warning( push )
#pragma warning( disable : 4245)
#include <asmjit/asmjit.h>
#pragma warning( pop )

#include "headers/Enums.hpp"
class ILCallback {
public:
	ILCallback() = default;
	~ILCallback();
	uint64_t getJitFunc(const PLH::CallConv conv);

	/* all mem calculations assume rsp/rbp are values BEFORE execution but AFTER call,
	i.e about to exec prolog. */
	asmjit::Operand getRegForArg(const uint8_t idx, const PLH::CallConv conv) const;
private:
	// asmjit's memory manager, manages JIT'd code
	asmjit::VMemMgr m_mem; 
	uint64_t m_callbackBuf;
};