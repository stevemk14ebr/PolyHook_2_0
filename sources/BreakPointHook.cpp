#include "headers/Exceptions/BreakPointHook.hpp"

PLH::BreakPointHook::BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;
	m_impls[fnAddress] = this;
}

PLH::BreakPointHook::BreakPointHook(const char* fnAddress, const char* fnCallback) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;
	m_impls[(uint64_t)fnAddress] = this;
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
	uint64_t ip = ExceptionInfo->ContextRecord->XIP;
	unHook();
	
	return EXCEPTION_CONTINUE_EXECUTION;
}