#include "polyhook2/PE/EatHook.hpp"

PLH::EatHook::EatHook(const std::string& apiName, const std::wstring& moduleName, const char* fnCallback, uint64_t* userOrigVar)
	: EatHook(apiName, moduleName, (uint64_t)fnCallback, userOrigVar)
{}

PLH::EatHook::EatHook(const std::string& apiName, const std::wstring& moduleName, const uint64_t fnCallback, uint64_t* userOrigVar)
    : EatHook(apiName, moduleName, nullptr, fnCallback, userOrigVar)
{}

PLH::EatHook::EatHook(const std::string& apiName, const HMODULE moduleHandle, const char* fnCallback, uint64_t* userOrigVar)
    : EatHook(apiName, moduleHandle, (uint64_t)fnCallback, userOrigVar)
{}

PLH::EatHook::EatHook(const std::string& apiName, const HMODULE moduleHandle, const uint64_t fnCallback, uint64_t* userOrigVar)
    : EatHook(apiName, L"", moduleHandle, fnCallback, userOrigVar)
{}

PLH::EatHook::EatHook(std::string apiName, std::wstring moduleName, const  HMODULE moduleHandle, const uint64_t fnCallback, uint64_t* userOrigVar)
	: m_moduleName(std::move(moduleName))
	, m_apiName(std::move(apiName))
	, m_fnCallback(fnCallback)
	, m_userOrigVar(userOrigVar)
	, m_allocator(64, 64) // arbitrary, size is big enough but an overshoot
	, m_trampoline(0)
	, m_moduleBase((uint64_t)moduleHandle)
	, m_origFunc(0)
{}

bool PLH::EatHook::hook() {
	assert(m_userOrigVar != nullptr);
	uint32_t* pExport = FindEatFunction();
	if (pExport == nullptr)
		return false;

	auto offset = (size_t)(m_fnCallback - m_moduleBase);

	/* account for when offset to our function is beyond EAT slots size. We
	instead allocate a small trampoline within +- 2GB which will do the full
	width jump to the final destination, and point the EAT to the stub.*/
	if (offset > std::numeric_limits<uint32_t>::max()) {
		m_trampoline = (uint64_t)m_allocator.allocate(m_moduleBase, PLH::calc_2gb_above(m_moduleBase));
		if (m_trampoline == 0) {
			Log::log("EAT hook offset is > 32bit's. Allocation of trampoline necessary and failed to find free page within range", ErrorLevel::INFO);
			return false;
		}

		MemoryProtector protector(m_trampoline, 64, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

		PLH::ZydisDisassembler::writeEncoding(makeAgnosticJmp(m_trampoline, m_fnCallback), *this);
		offset = (size_t)(m_trampoline - m_moduleBase);

		Log::log("EAT hook offset is > 32bit's. Allocation of trampoline necessary", ErrorLevel::INFO);
	}

	// Just like IAT, EAT is by default a writeable section
	// any EAT entry must be an offset
	MemoryProtector prot((uint64_t)pExport, sizeof(uintptr_t), ProtFlag::R | ProtFlag::W, *this);
	m_origFunc = *pExport; // original offset
	*pExport = (uint32_t)offset;
	m_hooked = true;
	*m_userOrigVar = m_moduleBase + m_origFunc; // original pointer (base + off)
	return true;
}

bool PLH::EatHook::unHook() {
	assert(m_userOrigVar != nullptr);
	assert(m_hooked);
	if (!m_hooked) {
		Log::log("EatHook unhook failed: no hook present", ErrorLevel::SEV);
		return false;
	}

	uint32_t* pExport = FindEatFunction();
	if (pExport == nullptr)
		return false;

	MemoryProtector prot((uint64_t)pExport, sizeof(uintptr_t), ProtFlag::R | ProtFlag::W, *this);
	*pExport = (uint32_t)m_origFunc;
	m_hooked = false;
	*m_userOrigVar = NULL;

	// TODO: change hook to re-use existing trampoline rather than free-ing here to avoid overwrite later and dangling pointer
	if (m_trampoline) {
		m_allocator.deallocate(m_trampoline);
		m_trampoline = 0;
	}
	return true;
}

uint32_t* PLH::EatHook::FindEatFunction() {
	if(!m_moduleBase){
		m_moduleBase = FindModule();
	}

	if(!m_moduleBase){
		Log::log("EAT | Failed to module base", ErrorLevel::SEV);
		return nullptr;
	}

	return FindEatFunctionInModule();
}

uint64_t PLH::EatHook::FindModule() {
#if defined(_WIN64)
	PEB* peb = (PPEB)__readgsqword(0x60);
#else
	PEB* peb = (PPEB)__readfsdword(0x30);
#endif

	auto* ldr = (PPEB_LDR_DATA)peb->Ldr;
	auto* dte = (LDR_DATA_TABLE_ENTRY*)ldr->InLoadOrderModuleList.Flink;

	// Empty module name implies current process
	if(m_moduleName.empty()){
		return (uint64_t)(dte->DllBase);
	}

	const auto useFullPath = std::filesystem::path(m_moduleName).is_absolute();

	// iterate over loaded modules to find the target module
	while (dte->DllBase != nullptr) {
		const auto peb_module = useFullPath ? dte->FullDllName: dte->BaseDllName;

		const ci_wstring_view pebModuleName{peb_module.Buffer, peb_module.Length / sizeof(wchar_t)};

		// Perform case-insensitive comparison
		const auto maxCharCount = std::min(pebModuleName.length(), m_moduleName.length());
		if(_wcsnicmp(pebModuleName.data(), m_moduleName.c_str(), maxCharCount) == 0){
			// std::wcout << L"Found module: " << path_or_name << std::endl;
			return (uint64_t)(dte->DllBase);
		}

		dte = (LDR_DATA_TABLE_ENTRY*)dte->InLoadOrderLinks.Flink;
	}

    Log::log("EAT | Failed to automatically find module", ErrorLevel::SEV);

	return 0;
}

uint32_t* PLH::EatHook::FindEatFunctionInModule() const {
    if (m_moduleBase == NULL) {
        return nullptr;
    }

	auto* pDos = (IMAGE_DOS_HEADER*)m_moduleBase;
	auto* pNT = RVA2VA(IMAGE_NT_HEADERS*, m_moduleBase, pDos->e_lfanew);
	auto* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

	if (pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL) {
		Log::log("PEs without export tables are unsupported", ErrorLevel::SEV);
		return nullptr;
	}

	auto* pExports = RVA2VA(IMAGE_EXPORT_DIRECTORY*, m_moduleBase, pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	auto* pAddressOfFunctions = RVA2VA(uint32_t*, m_moduleBase, pExports->AddressOfFunctions);
	auto* pAddressOfNames = RVA2VA(uint32_t*, m_moduleBase, pExports->AddressOfNames);
	auto* pAddressOfNameOrdinals = RVA2VA(uint16_t*, m_moduleBase, pExports->AddressOfNameOrdinals);

	for (uint32_t i = 0; i < pExports->NumberOfNames; i++) {
        if(my_narrow_stricmp(RVA2VA(char*, m_moduleBase, pAddressOfNames[i]), m_apiName.c_str()) != 0){
			continue;
		}

		// std::cout << RVA2VA(char*, m_moduleBase, pAddressOfNames[i]) << std::endl;
		const uint16_t iExportOrdinal = pAddressOfNameOrdinals[i];

		return &pAddressOfFunctions[iExportOrdinal];
	}

	Log::log("API not found before end of EAT", ErrorLevel::SEV);
	return nullptr;
}
