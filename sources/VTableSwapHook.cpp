#include "polyhook2/Virtuals/VTableSwapHook.hpp"

PLH::VTableSwapHook::VTableSwapHook(const char* Class, const VFuncMap& redirectMap) 
	: VTableSwapHook((uint64_t)Class, redirectMap)
{}

PLH::VTableSwapHook::VTableSwapHook(const uint64_t Class)
	: VTableSwapHook(Class, PLH::VFuncMap{ })
{}

PLH::VTableSwapHook::VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap) 
	: m_newVtable(nullptr)
	, m_origVtable(nullptr)
	, m_class(Class)
	, m_vFuncCount(0)
	, m_redirectMap(redirectMap)
	, m_origVFuncs()
{}

bool PLH::VTableSwapHook::hook() {
	assert(!m_hooked);
	if (m_hooked) {
		Log::log("vtable hook failed: hook already present", ErrorLevel::SEV);
		return false;
	}

	MemoryProtector prot(m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this);
	m_origVtable = *(uintptr_t**)m_class;
	m_vFuncCount = countVFuncs();
	assert(m_vFuncCount > 0);
	if (m_vFuncCount <= 0)
	{
		Log::log("vtable hook failed: class has no virtual functions", ErrorLevel::SEV);
		return false;
	}

	m_newVtable.reset(new uintptr_t[m_vFuncCount]);

	// deep copy orig vtable into new
	memcpy(m_newVtable.get(), m_origVtable, sizeof(uintptr_t) * m_vFuncCount);

	for (const auto& p : m_redirectMap) {
		assert(p.first < m_vFuncCount);
		if (p.first >= m_vFuncCount) {
			Log::log("vtable hook failed: index exceeds virtual function count", ErrorLevel::SEV);
			m_newVtable = nullptr;
			m_origVFuncs.clear();
			return false;
		}

		// redirect ptr at VTable[i]
		m_origVFuncs[p.first] = (uint64_t)m_newVtable[p.first];
		m_newVtable[p.first] = (uintptr_t)p.second;
	}

	*(uint64_t**)m_class = (uint64_t*)m_newVtable.get();
	m_hooked = true;
	Log::log("vtable hooked", ErrorLevel::INFO);
	return true;
}

bool PLH::VTableSwapHook::unHook() {
	assert(m_hooked);
	if (!m_hooked) {
		Log::log("vtable unhook failed: no hook present", ErrorLevel::SEV);
		return false;
	}

	MemoryProtector prot(m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this);
	*(uint64_t**)m_class = (uint64_t*)m_origVtable;
	
	m_newVtable.reset();

	m_hooked = false;
	m_origVtable = nullptr;
	Log::log("vtable unhooked", ErrorLevel::INFO);
	return true;
}

uint16_t PLH::VTableSwapHook::countVFuncs() {
	uint16_t count = 0;
	for (;; count++) {
		// if you have more than 500 vfuncs you have a problem and i don't support you :)
		if (!IsValidPtr((void*)m_origVtable[count]) || count > 500)
			break;
	}
	return count;
}

const PLH::VFuncMap& PLH::VTableSwapHook::getOriginals() const {
	return m_origVFuncs;
}