#pragma warning( push )
#pragma warning( disable : 4245)
#include <asmjit/asmjit.h>
#pragma warning( pop )

#pragma warning( disable : 4200)
#include "headers/ErrorLog.hpp"
#include "headers/Enums.hpp"

#include <vector>
namespace PLH {
	class ILCallback {
	public:
		struct Parameters {
			// must be char* for aliasing rules to work when reading back out
			unsigned char* getArgPtr(const uint8_t idx) const {
				return (unsigned char*)&m_arguments[idx];
			}

			// asm depends on this specific type
			uint64_t m_arguments[];
		};
		typedef void(*tUserCallback)(const Parameters* params, const uint8_t count);
		
		ILCallback() = default;
		~ILCallback();
		uint64_t getJitFunc(const asmjit::FuncSignature sig, const tUserCallback callback);
		uint64_t* getTrampolineHolder();
	private:
		// does a given type fit in a general purpose register (i.e. is it integer type)
		bool isGeneralReg(const uint8_t typeId) const;
		// float, double, simd128
		bool isXmmReg(const uint8_t typeId) const;

		// asmjit's memory manager, manages JIT'd code
		asmjit::VMemMgr m_mem;
		uint64_t m_callbackBuf;
		asmjit::X86Mem argsStack;

		// ptr to trampoline allocated by hook, we hold this so user doesn't need to.
		uint64_t m_trampolinePtr; 
	};
}
