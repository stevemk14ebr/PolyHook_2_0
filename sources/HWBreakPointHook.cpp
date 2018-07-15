#include "headers/Exceptions/HWBreakPointHook.hpp"

#include "headers/Exceptions/BreakPointHook.hpp"

PLH::HWBreakPointHook::HWBreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;
	m_impls[fnAddress] = this;
}

PLH::HWBreakPointHook::HWBreakPointHook(const char* fnAddress, const char* fnCallback) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;
	m_impls[(uint64_t)fnAddress] = this;
}

bool PLH::HWBreakPointHook::hook() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentThread(), &ctx)) {
		ErrorLog::singleton().push("Failed to get thread context", ErrorLevel::SEV);
		return false;
	}

	bool freeReg = false;
	for(m_regIdx = 0; m_regIdx < 4; m_regIdx++) {
		if ((ctx.Dr7 & (1 << (m_regIdx * 2))) == 0) {
			freeReg = true;
			break;
		}
	}

	if (!freeReg) {
		ErrorLog::singleton().push("All HW BP's are used", ErrorLevel::SEV);
		return false;
	}

	assert(m_regIdx < 4);

	switch (m_regIdx) {
	case 0:
		ctx.Dr0 = (decltype(ctx.Dr0))m_fnAddress;
		break;
	case 1:
		ctx.Dr1 = (decltype(ctx.Dr1))m_fnAddress;
		break;
	case 2:
		ctx.Dr2 = (decltype(ctx.Dr2))m_fnAddress;
		break;
	case 3:
		ctx.Dr3 = (decltype(ctx.Dr3))m_fnAddress;
		break;
	}

	ctx.Dr7 |= 1 << (2 * m_regIdx);

	// undefined, suspendthread needed
	if (!SetThreadContext(GetCurrentThread(), &ctx)) {
		ErrorLog::singleton().push("Failed to set thread context", ErrorLevel::SEV);
	}

	return true;
}

bool PLH::HWBreakPointHook::unHook() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentThread(), &ctx)) {
		ErrorLog::singleton().push("Failed to get thread context", ErrorLevel::SEV);
		return false;
	}

	ctx.Dr7 &= ~(1 << (2 * m_regIdx));

	//Still need to call suspend thread
	if (!SetThreadContext(GetCurrentThread(), &ctx)) {
		ErrorLog::singleton().push("Failed to set thread context", ErrorLevel::SEV);
		return false;
	}
	return true;
}

LONG PLH::HWBreakPointHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) {
	ExceptionInfo->ContextRecord->Dr7 &= ~(1 << (2 * m_regIdx));
	ExceptionInfo->ContextRecord->XIP = (decltype(ExceptionInfo->ContextRecord->XIP))m_fnCallback;
	return EXCEPTION_CONTINUE_EXECUTION;
}

