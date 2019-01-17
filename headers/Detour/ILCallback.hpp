#pragma warning( push )
#pragma warning( disable : 4245)
#include <asmjit/asmjit.h>
#pragma warning( pop )

#pragma warning( disable : 4200)
#include "headers/ErrorLog.hpp"
#include "headers/Enums.hpp"

#include "headers/PageAllocator.hpp"

#include <iostream>
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

		struct ReturnValue {
			unsigned char* getRetPtr() const {
				return (unsigned char*)&m_retVal;
			}
			uint64_t m_retVal;
		};

		typedef void(*tUserCallback)(const Parameters* params, const uint8_t count, const ReturnValue* ret);
		
		ILCallback();
		~ILCallback();

		/* Construct a callback given the raw signature at runtime. 'Callback' param is the C stub to transfer to,
		where parameters can be modified through a structure which is written back to the parameter slots depending 
		on calling convention.*/
		uint64_t getJitFunc(const asmjit::FuncSignature& sig, const tUserCallback callback);

		/* Construct a callback given the typedef as a string. Types are any valid C/C++ data type (basic types), and pointers to
		anything are just a uintptr_t. Calling convention is defaulted to whatever is typical for the compiler you use, you can override with
		stdcall, fastcall, or cdecl (cdecl is default on x86). On x64 those map to the same thing.*/
		uint64_t getJitFunc(const std::string& retType, const std::vector<std::string>& paramTypes, const tUserCallback callback, std::string callConv = "");
		uint64_t* getTrampolineHolder();
	private:
		// does a given type fit in a general purpose register (i.e. is it integer type)
		bool isGeneralReg(const uint8_t typeId) const;
		// float, double, simd128
		bool isXmmReg(const uint8_t typeId) const;

		asmjit::CallConv::Id getCallConv(const std::string& conv);
		uint8_t getTypeId(const std::string& type);

		PageAllocator m_mem;
		uint64_t m_callbackBuf;
		asmjit::x86::Mem argsStack;

		// ptr to trampoline allocated by hook, we hold this so user doesn't need to.
		uint64_t m_trampolinePtr; 
	};
}
