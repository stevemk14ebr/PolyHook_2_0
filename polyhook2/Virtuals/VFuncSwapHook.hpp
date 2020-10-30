#ifndef POLYHOOK_2_0_VFUNCSWAPHOOK_HPP
#define POLYHOOK_2_0_VFUNCSWAPHOOK_HPP

#include <cassert>
#include <map>

#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {
typedef std::map<uint16_t, uint64_t> VFuncMap;

class VFuncSwapHook : public PLH::IHook {
public:
	VFuncSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);
	VFuncSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs);
	virtual ~VFuncSwapHook() {
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	virtual HookType getType() const override {
		return HookType::VTableSwap;
	}
private:
	uint16_t countVFuncs();
	uint64_t  m_class;
	uintptr_t* m_vtable;

	uint16_t  m_vFuncCount;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap m_origVFuncs;
	VFuncMap* m_userOrigMap;
};
}
#endif