#include "headers/Exceptions/PageFaultHook.hpp"

PLH::PageFaultHook::PageFaultHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;
	assert(m_impls.find(m_fnAddress) == m_impls.end());
	m_impls[fnAddress] = this;
}

PLH::PageFaultHook::PageFaultHook(const char* fnAddress, const char* fnCallback) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;
	assert(m_impls.find(m_fnAddress) == m_impls.end());
	m_impls[(uint64_t)fnAddress] = this;
}

PLH::PageFaultHook::~PageFaultHook() {
	m_impls.erase(m_fnAddress);
}

bool PLH::PageFaultHook::hook() {
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((void*)m_fnAddress, &mbi, sizeof(mbi));

	if (mbi.Protect & PAGE_NOACCESS) {
		ErrorLog::singleton().push("Cannot hook a function on a NO_ACCESS page", ErrorLevel::SEV);
		return false;
	}

	uint64_t pHandler = (uint64_t)MemFnPtr(&PageFaultHook::OnException);
	if (AreInSamePage(pHandler, m_fnAddress)) {
		ErrorLog::singleton().push("Cannot hook a function on same page as VEH", ErrorLevel::SEV);
		return false;
	}

	DWORD OldProtection;
	VirtualProtect((void*)m_fnAddress, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtection);
	return true;
}

bool PLH::PageFaultHook::unHook() {
	/*Force an exception, catch it, continue execution, and don't restore protection.
	This effectively unhooks this type of hook, mark volatile so compiler doesn't optimize read away*/
	volatile uint8_t GenerateExceptionRead = *(uint8_t*)m_fnAddress;
	GenerateExceptionRead += 1;
	return true;
}

LONG PLH::PageFaultHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE)
		return EXCEPTION_CONTINUE_SEARCH;

	ExceptionInfo->ContextRecord->XIP = (decltype(ExceptionInfo->ContextRecord->XIP))m_fnCallback;
	return EXCEPTION_CONTINUE_EXECUTION;
}

