#include "headers/Exceptions/BreakPointHook.hpp"

PLH::BreakPointHook::BreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_impls[fnAddress] = this;
}

bool PLH::BreakPointHook::hook() {
	return true;
}

bool PLH::BreakPointHook::unHook() {
	return true;
}

LONG PLH::BreakPointHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) const {
	uint64_t ip = ExceptionInfo->ContextRecord->XIP;

	return EXCEPTION_CONTINUE_SEARCH;
}