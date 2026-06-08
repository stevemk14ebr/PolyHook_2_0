#include "polyhook2/Virtuals/VTableSwapHook.hpp"
#include "polyhook2/ErrorLog.hpp"

PLH::VTableSwapHook::VTableSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* userOrigMap)
	: VTableSwapHook((uint64_t)Class, redirectMap, userOrigMap)
{}

PLH::VTableSwapHook::VTableSwapHook(const uint64_t Class, VFuncMap* userOrigMap)
	: VTableSwapHook(Class, PLH::VFuncMap{ }, userOrigMap)
{}

PLH::VTableSwapHook::VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* userOrigMap)
	: m_newVtable(nullptr)
	, m_origVtable(nullptr)
	, m_class(Class)
	, m_vFuncCount(0)
	, m_redirectMap(redirectMap)
	, m_userOrigMap(userOrigMap)
{}

// Platform prefix sizes (in pointer-width units)
#if defined(_MSC_VER)
	static constexpr size_t VTABLE_PREFIX_ENTRIES = 1;  // RTTI Complete Object Locator (MSVC ABI)
#else
	static constexpr size_t VTABLE_PREFIX_ENTRIES = 2;  // offset-to-top + type_info* (Itanium ABI)
#endif

bool PLH::VTableSwapHook::hook() {
	assert(m_userOrigMap != nullptr);
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

	// +PREFIX_ENTRIES to include RTTI data before the function pointers
	const size_t totalEntries = m_vFuncCount + VTABLE_PREFIX_ENTRIES;
	m_newVtable.reset(new uintptr_t[totalEntries]);

	// Copy including the RTTI prefix
	uintptr_t* srcBase = m_origVtable - VTABLE_PREFIX_ENTRIES;
	memcpy(m_newVtable.get(), srcBase, sizeof(uintptr_t) * totalEntries);

	// The vtable pointer the class stores must point PAST the prefix
	uintptr_t* newVtableStart = m_newVtable.get() + VTABLE_PREFIX_ENTRIES;

	for (const auto& p : m_redirectMap) {
		assert(p.first < m_vFuncCount);
		if (p.first >= m_vFuncCount) {
			Log::log("vtable hook failed: index exceeds virtual function count", ErrorLevel::SEV);
			m_newVtable = nullptr;
			(*m_userOrigMap).clear();
			return false;
		}

		// redirect ptr at VTable[i]
		(*m_userOrigMap)[p.first] = (uint64_t)newVtableStart[p.first];
		newVtableStart[p.first] = (uintptr_t)p.second;
	}

	*(uint64_t**)m_class = (uint64_t*)newVtableStart;
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

	(*m_userOrigMap).clear();

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
