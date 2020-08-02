#include "polyhook2/Exceptions/HWBreakPointHook.hpp"

PLH::HWBreakPointHook::HWBreakPointHook(const uint64_t fnAddress, const uint64_t fnCallback, HANDLE hThread) : AVehHook() {
	m_fnCallback = fnCallback;
	m_fnAddress = fnAddress;

	auto entry = AVehHookImpEntry(fnAddress, this);
	assert(m_impls.find(entry) == m_impls.end());
	m_impls.insert(entry);

	m_hThread = hThread;
}

PLH::HWBreakPointHook::HWBreakPointHook(const char* fnAddress, const char* fnCallback, HANDLE hThread) : AVehHook() {
	m_fnCallback = (uint64_t)fnCallback;
	m_fnAddress = (uint64_t)fnAddress;

	auto entry = AVehHookImpEntry((uint64_t)fnAddress, this);
	assert(m_impls.find(entry) == m_impls.end());
	m_impls.insert(entry);

	m_hThread = hThread;
}

PLH::HWBreakPointHook::~HWBreakPointHook() {
	m_impls.erase(AVehHookImpEntry(m_fnAddress, this));
}

bool PLH::HWBreakPointHook::hook()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(m_hThread, &ctx)) {
		Log::log("Failed to get thread context", ErrorLevel::SEV);
		return false;
	}

	bool freeReg = false;
	for (m_regIdx = 0; m_regIdx < 4; m_regIdx++) {
		if ((ctx.Dr7 & (1ULL << (m_regIdx * 2))) == 0) {
			freeReg = true;
			break;
		}
	}

	if (!freeReg) {
		Log::log("All HW BP's are used", ErrorLevel::SEV);
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

	ctx.Dr7 &= ~(3ULL << (16 + 4 * m_regIdx)); //00b at 16-17, 20-21, 24-25, 28-29 is execute bp
	ctx.Dr7 &= ~(3ULL << (18 + 4 * m_regIdx)); // size of 1 (val 0), at 18-19, 22-23, 26-27, 30-31
	ctx.Dr7 |= 1ULL << (2 * m_regIdx);

	// undefined, suspendthread needed
	if (!SetThreadContext(m_hThread, &ctx)) {
		Log::log("Failed to set thread context", ErrorLevel::SEV);
	}

	return true;
}

bool PLH::HWBreakPointHook::unHook() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(m_hThread, &ctx)) {
		Log::log("Failed to get thread context", ErrorLevel::SEV);
		return false;
	}

	ctx.Dr7 &= ~(1ULL << (2 * m_regIdx));

	//Still need to call suspend thread
	if (!SetThreadContext(m_hThread, &ctx)) {
		Log::log("Failed to set thread context", ErrorLevel::SEV);
		return false;
	}
	return true;
}

LONG PLH::HWBreakPointHook::OnException(EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	ExceptionInfo->ContextRecord->Dr7 &= ~(1ULL << (2 * m_regIdx));
	ExceptionInfo->ContextRecord->XIP = (decltype(ExceptionInfo->ContextRecord->XIP))m_fnCallback;
	return EXCEPTION_CONTINUE_EXECUTION;
}

