#include "headers/Exceptions/AVehHook.hpp"

PLH::RefCounter PLH::AVehHook::m_refCount;
void* PLH::AVehHook::m_hHandler;
std::map<uint64_t, PLH::AVehHook*> PLH::AVehHook::m_impls;

//https://reverseengineering.stackexchange.com/questions/14992/what-are-the-vectored-continue-handlers
PLH::AVehHook::AVehHook() {
	if (m_refCount.m_count == 0) {
		m_hHandler = AddVectoredExceptionHandler(1, &AVehHook::Handler);
		if (m_hHandler == NULL) {
			std::cout << "VEH FAILED!" << std::endl;
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
	
	printf("Got top level exception: %I64X %X\n", ip, ExceptionCode);
	switch (ExceptionCode) {
	case 0xE06D7363:
		std::cout << "C++ exception thrown" << std::endl;
		break;
	case EXCEPTION_BREAKPOINT:
		printf("Exception Breakpoint\n");
	case EXCEPTION_SINGLE_STEP:
		printf("Exception SS\n");
		// lookup which instance to forward exception to
		if (m_impls.find(ip) != m_impls.end()) {
			printf("Dispatching\n");
			return m_impls.at(ip)->OnException(ExceptionInfo);
		}
		break;
	case EXCEPTION_GUARD_PAGE:
		printf("Exception guard page\n");

		// dispatch to handler impl if found
		if (m_impls.find(ip) != m_impls.end()) {
			return m_impls.at(ip)->OnException(ExceptionInfo);
		}

		decltype(m_impls)::iterator it;
		for (it = m_impls.begin(); it != m_impls.end(); it++) {
			if (AreInSamePage(it->first, ip))
				return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}