#include "polyhook2/Exceptions/AVehHook.hpp"

PLH::RefCounter PLH::AVehHook::m_refCount;
void* PLH::AVehHook::m_hHandler;
std::map<uint64_t, PLH::AVehHook*> PLH::AVehHook::m_impls;

// https://reverseengineering.stackexchange.com/questions/14992/what-are-the-vectored-continue-handlers
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
	case 0xE06D7363: // oooh aaahh a magic value
        std::cout << "C++ exception thrown" << std::endl;
		break;
	case EXCEPTION_BREAKPOINT:
	case EXCEPTION_SINGLE_STEP:
		// lookup which instance to forward exception to
        const auto it = m_impls.find(ip);

		if (it != m_impls.end()) {
			return it->second->OnException(ExceptionInfo);
		}
		break;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}