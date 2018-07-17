#include "headers/Virtuals/VTableSwapHook.hpp"

PLH::VTableSwapHook::VTableSwapHook(const char* Class, const VFuncMap& redirectMap) {
	m_class = (uint64_t)Class;
	m_redirectMap = redirectMap;
	m_newVtable = nullptr;
}

PLH::VTableSwapHook::VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap) {
	m_class = Class;
	m_redirectMap = redirectMap;
	m_newVtable = nullptr;
}

PLH::VTableSwapHook::~VTableSwapHook() {
	if (m_newVtable != nullptr) {
		delete[] m_newVtable;
		m_newVtable = nullptr;
	}
}

bool PLH::VTableSwapHook::hook() {
	MemoryProtector prot(m_class, sizeof(void*), ProtFlag::R | ProtFlag::W);
	m_origVtable = *(uintptr_t**)m_class;
	m_vFuncCount = countVFuncs();
	if (m_vFuncCount <= 0)
		return false;

	m_newVtable = (uintptr_t*) new uintptr_t[m_vFuncCount];
	if (m_newVtable == nullptr)
		return false;

	// deep copy orig vtable into new
	memcpy(m_newVtable, m_origVtable, sizeof(uintptr_t) * m_vFuncCount);

	for (const auto& p : m_redirectMap) {
		assert(p.first < m_vFuncCount);
		if (p.first >= m_vFuncCount)
			return false;

		// redirect ptr at VTable[i]
		m_origVFuncs[p.first] = (uint64_t)m_newVtable[p.first];
		m_newVtable[p.first] = (uintptr_t)p.second;
	}

	*(uint64_t**)m_class = (uint64_t*)m_newVtable;
	m_Hooked = true;
	return true;
}

bool PLH::VTableSwapHook::unHook() {
	assert(m_Hooked);
	if (!m_Hooked)
		return false;

	MemoryProtector prot(m_class, sizeof(void*), ProtFlag::R | ProtFlag::W);
	*(uint64_t**)m_class = (uint64_t*)m_origVtable;
	
	if (m_newVtable != nullptr) {
		delete[] m_newVtable;
		m_newVtable = nullptr;
	}

	m_Hooked = false;
	m_origVtable = nullptr;
	m_newVtable = nullptr;
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

PLH::VFuncMap PLH::VTableSwapHook::getOriginals() const {
	return m_origVFuncs;
}