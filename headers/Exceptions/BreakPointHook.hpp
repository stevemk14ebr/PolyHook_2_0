#ifndef POLYHOOK_2_0_BPHOOK_HPP
#define POLYHOOK_2_0_BPHOOK_HPP

#include <cassert>
#include "headers/Exceptions/AVehHook.hpp"
#pragma warning(disable: 4189)

namespace PLH {
class BreakPointHook : public AVehHook {
public:
	BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback);
	virtual bool hook() override;
	virtual bool unHook() override;
private:
	uint64_t m_fnCallback;
	LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) const override;
};
}
#endif