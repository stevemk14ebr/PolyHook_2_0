#include "headers/Exceptions/AVehHook.hpp"

PLH::RefCounter PLH::AVehHook::m_refCount;
void* PLH::AVehHook::m_hHandler;
std::map<uint64_t, PLH::AVehHook*> PLH::AVehHook::m_impls;

PLH::AVehHook::AVehHook() {
	if (m_refCount.m_count == 0) {
		m_hHandler = AddVectoredExceptionHandler(1, &AVehHook::Handler);
		if (m_hHandler == NULL) {
			ErrorLog::singleton().push("Failed to add VEH", ErrorLevel::SEV);
		}
	}

	m_refCount.m_count++;
}

PLH::AVehHook::~AVehHook() {
	assert(m_refCount.m_count >= 1);

	m_refCount.m_count--;
	if (m_refCount.m_count == 0) {
		assert(m_hHandler != nullptr);
		ULONG status = RemoveVectoredExceptionHandler(m_hHandler);
		m_hHandler = nullptr;
		if (status == 0) {
			ErrorLog::singleton().push("Failed to remove VEH", ErrorLevel::SEV);
		}
	}
}

LONG CALLBACK PLH::AVehHook::Handler(EXCEPTION_POINTERS* ExceptionInfo) {
	DWORD ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	uint64_t ip = ExceptionInfo->ContextRecord->XIP;
	
	switch (ExceptionCode) {
	case EXCEPTION_BREAKPOINT:
	case EXCEPTION_SINGLE_STEP:
	case EXCEPTION_GUARD_PAGE:
		// lookup which instance to forward exception to
		if (m_impls.find(ip) != m_impls.end()) {
			return m_impls.at(ip)->OnException(ExceptionInfo);
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}