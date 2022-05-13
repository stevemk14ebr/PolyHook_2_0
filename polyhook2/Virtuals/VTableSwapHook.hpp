#ifndef POLYHOOK_2_0_VTBLSWAPHOOK_HPP
#define POLYHOOK_2_0_VTBLSWAPHOOK_HPP

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {

typedef std::map<uint16_t, uint64_t> VFuncMap;

class VTableSwapHook : public PLH::IHook {
public:
	VTableSwapHook(const uint64_t Class, VFuncMap* origVFuncs);
	VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);
	VTableSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);

	virtual ~VTableSwapHook() {
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	virtual HookType getType() const override {
		return HookType::VTableSwap;
	}
protected:
	uint16_t countVFuncs();

	std::unique_ptr<uintptr_t[]> m_newVtable;
	uintptr_t* m_origVtable;

	uint64_t  m_class;

	uint16_t  m_vFuncCount;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap* m_userOrigMap;
};

}

#endif