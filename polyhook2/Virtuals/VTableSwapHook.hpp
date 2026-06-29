#ifndef POLYHOOK_2_0_VTBLSWAPHOOK_HPP
#define POLYHOOK_2_0_VTBLSWAPHOOK_HPP

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {

typedef std::map<uint16_t, uint64_t> VFuncMap;

enum class VTableRTTIMode {
    None,       // no prefix (e.g. -fno-rtti, manually built vtable)
    MSVC,       // 1 entry: RTTI Complete Object Locator
    Itanium,    // 2 entries: offset-to-top + type_info* (GCC/Clang)

#if defined(_MSC_VER)
    Default = MSVC,
#else
    Default = Itanium,
#endif
};

class VTableSwapHook : public PLH::IHook {
public:
	VTableSwapHook(const uint64_t Class, VFuncMap* origVFuncs, VTableRTTIMode rttiMode = VTableRTTIMode::Default);
	VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs, VTableRTTIMode rttiMode = VTableRTTIMode::Default);
	VTableSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* origVFuncs, VTableRTTIMode rttiMode = VTableRTTIMode::Default);

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
	VTableRTTIMode  m_rttiMode;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap* m_userOrigMap;
};

}

#endif