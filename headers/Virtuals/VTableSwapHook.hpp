#ifndef POLYHOOK_2_0_VTBLSWAPHOOK_HPP
#define POLYHOOK_2_0_VTBLSWAPHOOK_HPP

#include <cassert>
#include <memory>
#include <map>

#include "headers/IHook.hpp"
#include "headers/MemProtector.hpp"
#include "headers/Misc.hpp"

namespace PLH {
typedef std::map<uint16_t, uint64_t> VFuncMap;

class VTableSwapHook : public PLH::IHook {
public:
	VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap);
	VTableSwapHook(const char* Class, const VFuncMap& redirectMap);
	~VTableSwapHook() override = default;

	const VFuncMap& getOriginals() const;

	bool hook() override;
	bool unHook() override;
	HookType getType() const override {
		return HookType::VTableSwap;
	}
private:
	uint16_t countVFuncs();

	std::unique_ptr<uintptr_t[]> m_newVtable;
	uintptr_t* m_origVtable;

	uint64_t  m_class;

	uint16_t  m_vFuncCount;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap m_origVFuncs;
	bool m_Hooked;
};
}
#endif
