#ifndef POLYHOOK_2_0_VTBLSWAPHOOK_HPP
#define POLYHOOK_2_0_VTBLSWAPHOOK_HPP

#include <cassert>
#include <map>

#include "headers/IHook.hpp"
#include "headers/MemProtector.hpp"

//Credit to Dogmatt on unknowncheats.me for IsValidPtr
// and https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
#ifdef _WIN64
#define _PTR_MAX_VALUE ((void*)0x000F000000000000)
#else
#define _PTR_MAX_VALUE ((void*)0xFFF00000)
#endif

inline bool IsValidPtr(void* p) { return (p >= (void*)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr; }

namespace PLH {
typedef std::map<uint16_t, uint64_t> VFuncMap;

	class VTableSwapHook : public PLH::IHook {
	public:
		VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap);
		VTableSwapHook(const char* Class, const VFuncMap& redirectMap);
		~VTableSwapHook();

		VFuncMap getOriginals() const;

		virtual bool hook() override;
		virtual bool unHook() override;
		virtual HookType getType() const override {
			return HookType::VTableSwap;
		}
	private:
		uint16_t countVFuncs();

		uintptr_t* m_newVtable;
		uintptr_t* m_origVtable;

		uint64_t  m_class;
		
		uint16_t  m_hkIndex;
		uint16_t  m_vFuncCount;

		// index -> ptr val 
		VFuncMap m_redirectMap;
		VFuncMap m_origVFuncs;
		bool m_NeedFree;
		bool m_Hooked;
	};
}
#endif