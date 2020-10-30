#ifndef POLYHOOK_2_0_HWBPHOOK_HPP
#define POLYHOOK_2_0_HWBPHOOK_HPP

#include <cassert>

#include "polyhook2/Exceptions/AVehHook.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {

class HWBreakPointHook : public AVehHook {
public:
	HWBreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback, HANDLE hThread);
	HWBreakPointHook(const char* fnAddress, const char* fnCallback, HANDLE hThread);
	~HWBreakPointHook() {
		m_impls.erase(AVehHookImpEntry(m_fnAddress, this));
		if (m_hooked) {
			unHook();
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	auto getProtectionObject() {
		return finally([&] () {
			hook();
		});
	}
private:
	uint64_t m_fnCallback;
	uint64_t m_fnAddress;
	uint8_t m_regIdx;

	HANDLE m_hThread;

	LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) override;
};
}

#endif