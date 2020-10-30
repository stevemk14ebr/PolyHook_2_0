//https://github.com/odzhan/shellcode/blob/master/os/win/getapi/dynamic/getapi.c
//https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/
#include <string>
#include <iostream>
#include <algorithm>

#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/PE/PEB.hpp"
#include "polyhook2/ADisassembler.hpp"
#include "polyhook2/PageAllocator.hpp"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

namespace PLH {
class EatHook : public IHook {
public:
	EatHook(const std::string& apiName, const std::wstring& moduleName, const char* fnCallback, uint64_t* userOrigVar);
	EatHook(const std::string& apiName, const std::wstring& moduleName, const uint64_t fnCallback, uint64_t* userOrigVar);
	virtual ~EatHook() {
		// trampoline freed by pageallocator dtor
		if (m_allocator != nullptr) {
			delete m_allocator;
			m_allocator = nullptr;
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	
	virtual HookType getType() const override {
		return HookType::EAT;
	}
private:
	const uint16_t m_trampolineSize = 32;
	uint32_t* FindEatFunction(const std::string& apiName, const std::wstring& moduleName = L"");
	uint32_t* FindEatFunctionInModule(const std::string& apiName);

	std::wstring m_moduleName;
	std::string m_apiName;

	uint64_t m_fnCallback;
	uint64_t m_origFunc;
	uint64_t* m_userOrigVar;

	// only used if EAT offset points >= 2GB
	PageAllocator* m_allocator;
	uint64_t m_trampoline;

	uint64_t m_moduleBase;
};
}