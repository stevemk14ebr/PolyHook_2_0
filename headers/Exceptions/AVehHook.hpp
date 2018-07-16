#ifndef POLYHOOK_2_0_VEHHOOK_HPP
#define POLYHOOK_2_0_VEHHOOK_HPP

#include <cassert>
#include <map>

#include "headers/MemProtector.hpp"
#include "headers/ErrorLog.hpp"
#include "headers/IHook.hpp"
#include "headers/Enums.hpp"

namespace PLH {

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif // _WIN64

class RefCounter {
public:
	RefCounter() {
		m_count = 0;
	}

	uint16_t m_count;
};

static inline bool AreInSamePage(const uint64_t Addr1, const uint64_t Addr2) {
	//If VQ fails, be safe and say they are in same page
	MEMORY_BASIC_INFORMATION mbi1;
	ZeroMemory(&mbi1, sizeof(mbi1));
	if (!VirtualQuery(&Addr1, &mbi1, sizeof(mbi1)))
		return true;

	MEMORY_BASIC_INFORMATION mbi2;
	ZeroMemory(&mbi2, sizeof(mbi2));
	if (!VirtualQuery(&Addr2, &mbi2, sizeof(mbi2)))
		return true;

	if (mbi1.BaseAddress == mbi2.BaseAddress)
		return true;

	return false;
}

class AVehHook;
class AVehHook : public IHook {
public:
	AVehHook();
	~AVehHook();

	virtual HookType getType() const {
		return HookType::VEHHOOK;
	}
protected:
	// May not allocate or acquire synchonization objects in this
	virtual LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) = 0;

	static RefCounter m_refCount;
	static void* m_hHandler;
	static std::map<uint64_t, AVehHook*> m_impls;
	static LONG CALLBACK Handler(EXCEPTION_POINTERS* ExceptionInfo);
};
}

#endif