#ifndef POLYHOOK_2_0_PGFAULTHOOK_HPP
#define POLYHOOK_2_0_PGFAULTHOOK_HPP

#include <cassert>

#include "headers/Exceptions/AVehHook.hpp"
#include "headers/Misc.hpp"

namespace PLH {

// Cast a member function pointer that cannot have a reference taken to a void *
template <typename RET_TYPE, typename CLASS, typename...ARGs>
void* MemFnPtr(RET_TYPE(CLASS::*&&pOriginalFunction)(ARGs...)) {
	union {
		RET_TYPE(CLASS::*pMemFn)(ARGs...);
		void* voidPtr;
	} cast = {pOriginalFunction};
	static_assert(sizeof(cast.pMemFn) == sizeof(cast.voidPtr), "Cannot cast this member function pointer to a void*.  Not the same size.");
	return cast.voidPtr;
}

// Cast a member function pointer to a void*&
template <typename RET_TYPE, typename CLASS, typename...ARGs>
void*& MemFnPtr(RET_TYPE(CLASS::*&pOriginalFunction)(ARGs...)) {
	union {
		RET_TYPE(CLASS::*&pMemFn)(ARGs...);
		void*& voidPtr;
	} cast = {pOriginalFunction};
	static_assert(sizeof(cast.pMemFn) == sizeof(cast.voidPtr), "Cannot cast this member function pointer to a void*.  Not the same size.");
	return cast.voidPtr;
}

class PageFaultHook : public AVehHook {
public:
	PageFaultHook(const uint64_t fnAddress, const uint64_t fnCallback);
	PageFaultHook(const char* fnAddress, const char* fnCallback);
	~PageFaultHook();

	virtual bool hook() override;
	virtual bool unHook() override;
	auto getProtectionObject() {
		return finally([=] () {
			hook();
		});
	}
private:
	uint64_t m_fnCallback;
	uint64_t m_fnAddress;
	uint8_t m_regIdx;

	LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) override;
};
}

#endif