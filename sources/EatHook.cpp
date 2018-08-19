#include "headers/PE/EatHook.hpp"

PLH::EatHook::EatHook(const std::wstring& dllName, const std::string& apiName, const char* fnCallback, uint64_t* userOrigVar)
	: EatHook(dllName, apiName, (uint64_t)fnCallback, userOrigVar)
{}

PLH::EatHook::EatHook(const std::wstring& dllName, const std::string& apiName, const uint64_t fnCallback, uint64_t* userOrigVar)
	: m_dllName(dllName)
    , m_apiName(apiName)
    , m_userOrigVar(userOrigVar)
    , m_fnCallback(fnCallback)
{}

bool PLH::EatHook::hook() {
	assert(m_userOrigVar != nullptr);
	PDWORD pExport = FindEatFunction(m_dllName, m_apiName);
	if (pExport == nullptr)
		return false;

	// Just like IAT, EAT is by default a writeable section
	// any EAT entry must be an offset
	MemoryProtector prot((uint64_t)pExport, sizeof(uintptr_t), ProtFlag::R | ProtFlag::W);
	m_origFunc = *pExport;
	*pExport = (DWORD)(m_fnCallback - m_moduleBase);
	m_hooked = true;
	*m_userOrigVar = m_origFunc;
	return true;
}

bool PLH::EatHook::unHook() {
	assert(m_userOrigVar != nullptr);
	assert(m_hooked);
	if (!m_hooked)
		return false;

	PDWORD pExport = FindEatFunction(m_dllName, m_apiName);
	if (pExport == nullptr)
		return false;

	MemoryProtector prot((uint64_t)pExport, sizeof(uintptr_t), ProtFlag::R | ProtFlag::W);
	*pExport = (DWORD)m_origFunc;
	m_hooked = false;
	*m_userOrigVar = NULL;
	return true;
}

PDWORD PLH::EatHook::FindEatFunction(const std::wstring& dllName, const std::string& apiName) {
#if defined(_WIN64)
	PEB* peb = (PPEB)__readgsqword(0x60);
#else
	PEB* peb = (PPEB)__readfsdword(0x30);
#endif

	PDWORD pExportAddress = nullptr;
	PEB_LDR_DATA* ldr = (PPEB_LDR_DATA)peb->Ldr;

	// find loaded module from peb
	for (LDR_DATA_TABLE_ENTRY* dte = (LDR_DATA_TABLE_ENTRY*)ldr->InLoadOrderModuleList.Flink;
		 dte->DllBase != NULL;
		 dte = (LDR_DATA_TABLE_ENTRY*)dte->InLoadOrderLinks.Flink) {

		// TODO: create stricmp for UNICODE_STRING because this is really bad for performance
		std::wstring baseModuleName(dte->BaseDllName.Buffer, dte->BaseDllName.Length / sizeof(wchar_t));

		if (my_wide_stricmp(baseModuleName.c_str(), dllName.c_str()) != 0)
			continue;

		m_moduleBase = (uint64_t)dte->DllBase;

		pExportAddress = FindEatFunctionInModule(apiName);
		if (pExportAddress != nullptr)
			return pExportAddress;
	}

	if (pExportAddress == nullptr) {
		ErrorLog::singleton().push("Failed to find export address from requested dll", ErrorLevel::SEV);
	}
	return pExportAddress;
}

PDWORD PLH::EatHook::FindEatFunctionInModule(const std::string& apiName) {
	assert(m_moduleBase != NULL);
	if (m_moduleBase == NULL)
		return NULL;

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)m_moduleBase;
	IMAGE_NT_HEADERS* pNT = RVA2VA(IMAGE_NT_HEADERS*, m_moduleBase, pDos->e_lfanew);
	IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

	if (pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL) {
		ErrorLog::singleton().push("PEs without export tables are unsupported", ErrorLevel::SEV);
		return NULL;
	}

	IMAGE_EXPORT_DIRECTORY* pExports = RVA2VA(IMAGE_EXPORT_DIRECTORY*, m_moduleBase, pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pAddressOfFunctions = RVA2VA(PDWORD, m_moduleBase, pExports->AddressOfFunctions);
	PDWORD pAddressOfNames = RVA2VA(PDWORD, m_moduleBase, pExports->AddressOfNames);
	PWORD pAddressOfNameOrdinals = RVA2VA(PWORD, m_moduleBase, pExports->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExports->NumberOfFunctions; i++)
	{	
        if(my_narrow_stricmp(RVA2VA(PCHAR, m_moduleBase, pAddressOfNames[i]),
                             apiName.c_str()) != 0)
			continue;	 				

		WORD iExportOrdinal = RVA2VA(WORD, m_moduleBase, pAddressOfNameOrdinals[i]);
		PDWORD pExportAddress = &pAddressOfFunctions[iExportOrdinal];

		return pExportAddress;
	}

	ErrorLog::singleton().push("API not found before end of EAT", ErrorLevel::SEV);
	return nullptr;
}