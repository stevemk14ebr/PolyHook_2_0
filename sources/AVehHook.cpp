#include "polyhook2/Exceptions/AVehHook.hpp"

PLH::RefCounter PLH::AVehHook::m_refCount;
void* PLH::AVehHook::m_hHandler;
std::unordered_set<PLH::AVehHookImpEntry> PLH::AVehHook::m_impls;
PLH::eException PLH::AVehHook::m_onException;
PLH::eException PLH::AVehHook::m_onUnhandledException;

// https://reverseengineering.stackexchange.com/questions/14992/what-are-the-vectored-continue-handlers
PLH::AVehHook::AVehHook() {
	if (m_refCount.m_count == 0) {
		m_hHandler = AddVectoredExceptionHandler(1, &AVehHook::Handler);
		if (m_hHandler == NULL) {
			Log::log("Failed to add VEH", ErrorLevel::SEV);
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
			Log::log("Failed to remove VEH", ErrorLevel::SEV);
		}
	}
}

PLH::eException& PLH::AVehHook::EventException() {
	return m_onException;
}

PLH::eException& PLH::AVehHook::EventUnhandledException() {
	return m_onUnhandledException;
}

LONG CALLBACK PLH::AVehHook::Handler(EXCEPTION_POINTERS* ExceptionInfo) {
	DWORD ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	uint64_t ip = ExceptionInfo->ContextRecord->XIP;

	// invoke callback (let users filter)
	DWORD code = EXCEPTION_CONTINUE_SEARCH;
	if (m_onException && m_onException.Invoke(ExceptionInfo, &code))
		return code;

	switch (ExceptionCode) {
	case 0xE06D7363: // oooh aaahh a magic value
        std::cout << "C++ exception thrown" << std::endl;
		break;
	// these could all reasonably be hooked by someone
	case EXCEPTION_GUARD_PAGE:
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_BREAKPOINT:
	case EXCEPTION_SINGLE_STEP:
		// lookup which instance to forward exception to
		for (const auto& hk : m_impls) {
			switch (hk.type) {
			case AVehHookImpType::SINGLE:
				if (hk.startAddress == ip) {
					return hk.impl->OnException(ExceptionInfo);
				}
				break;
			case AVehHookImpType::RANGE:
				if (ip >= hk.startAddress && ip < hk.endAddress) {
					return hk.impl->OnException(ExceptionInfo);
				}
				break;
			}
		}
		break;
	default:
		// let users extend manually
		if (m_onUnhandledException && m_onUnhandledException.Invoke(ExceptionInfo, &code))
			return code;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}