#include "polyhook2/Exceptions/BreakPointHook.hpp"

PLH::BreakPointHook::BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;

	auto entry = AVehHookImpEntry(fnAddress, this);
	assert(m_impls.find(entry) == m_impls.end());
	m_impls.insert(entry);
}

PLH::BreakPointHook::BreakPointHook(const char* fnAddress, const char* fnCallback) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;

	auto entry = AVehHookImpEntry((uint64_t)fnAddress, this);
	assert(m_impls.find(entry) == m_impls.end());
	m_impls.insert(entry);
}

bool PLH::BreakPointHook::hook() {
	MemoryProtector prot(m_fnAddress, 1, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	m_origByte = *(uint8_t*)m_fnAddress;
	*(uint8_t*)m_fnAddress = 0xCC;
	m_hooked = true;
	return true;
}

bool PLH::BreakPointHook::unHook() {
	assert(m_hooked);
	if (!m_hooked) {
		Log::log("BPHook unhook failed: no hook present", ErrorLevel::SEV);
		return false;
	}

	MemoryProtector prot(m_fnAddress, 1, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	*(uint8_t*)m_fnAddress = m_origByte;
	m_hooked = false;
	return true;
}

LONG PLH::BreakPointHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
		return EXCEPTION_CONTINUE_SEARCH;

	// restored via getProtectionObject()
	unHook();
	ExceptionInfo->ContextRecord->XIP = (decltype(ExceptionInfo->ContextRecord->XIP))m_fnCallback;
	return EXCEPTION_CONTINUE_EXECUTION;
}

