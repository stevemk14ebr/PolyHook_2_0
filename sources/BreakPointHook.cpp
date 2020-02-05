#include "polyhook2/Exceptions/BreakPointHook.hpp"

PLH::BreakPointHook::BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;
	assert(m_impls.find(m_fnAddress) == m_impls.end());
	m_impls[fnAddress] = this;
}

PLH::BreakPointHook::BreakPointHook(const char* fnAddress, const char* fnCallback) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;
	assert(m_impls.find(m_fnAddress) == m_impls.end());
	m_impls[(uint64_t)fnAddress] = this;
}

PLH::BreakPointHook::~BreakPointHook() {
	m_impls.erase(m_fnAddress);
}

bool PLH::BreakPointHook::hook() {
	MemoryProtector prot(m_fnAddress, 1, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	m_origByte = *(uint8_t*)m_fnAddress;
	*(uint8_t*)m_fnAddress = 0xCC;
	return true;
}

bool PLH::BreakPointHook::unHook() {
	MemoryProtector prot(m_fnAddress, 1, ProtFlag::R | ProtFlag::W | ProtFlag::X);
	*(uint8_t*)m_fnAddress = m_origByte;
	return true;
}

LONG PLH::BreakPointHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
		return EXCEPTION_CONTINUE_SEARCH;

	unHook();
	ExceptionInfo->ContextRecord->XIP = (decltype(ExceptionInfo->ContextRecord->XIP))m_fnCallback;
	return EXCEPTION_CONTINUE_EXECUTION;
}

