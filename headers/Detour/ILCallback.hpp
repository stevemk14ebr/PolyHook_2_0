#pragma warning( push )
#pragma warning( disable : 4245)
#include <asmjit/asmjit.h>
#pragma warning( pop )

#pragma warning( disable : 4200)
#include "headers/Enums.hpp"

#include <vector>
namespace PLH {
	class ILCallback {
	public:
		struct Parameters {
			// asm depends on this specific type
			uint64_t m_arguments[];
		};
		typedef void(*tUserCallback)(const Parameters* params);
		
		ILCallback() = default;
		~ILCallback();
		uint64_t getJitFunc(const asmjit::FuncSignature sig, const tUserCallback callback);
	private:
		// asmjit's memory manager, manages JIT'd code
		asmjit::VMemMgr m_mem;
		uint64_t m_callbackBuf;
		asmjit::X86Mem argsStack;
	};
}
