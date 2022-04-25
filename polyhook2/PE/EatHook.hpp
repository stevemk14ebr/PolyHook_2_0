//https://github.com/odzhan/shellcode/blob/master/os/win/getapi/dynamic/getapi.c
//https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/PE/PEB.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
#include "polyhook2/RangeAllocator.hpp"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

namespace PLH {
class EatHook : public IHook {
public:
	EatHook(const std::string& apiName, const std::wstring& moduleName, const char* fnCallback, uint64_t* userOrigVar);
	EatHook(const std::string& apiName, const std::wstring& moduleName, const uint64_t fnCallback, uint64_t* userOrigVar);
	EatHook(const std::string& apiName, const HMODULE moduleHandle, const char* fnCallback, uint64_t* userOrigVar);
	EatHook(const std::string& apiName, const HMODULE moduleHandle, const uint64_t fnCallback, uint64_t* userOrigVar);
	virtual ~EatHook()
	{
		if (m_trampoline) {
			m_allocator.deallocate(m_trampoline);
			m_trampoline = 0;
		}
	}

	virtual bool hook() override;
	virtual bool unHook() override;
	
	virtual HookType getType() const override {
		return HookType::EAT;
	}
protected:
    EatHook(std::string apiName, std::wstring moduleName, HMODULE moduleHandle, uint64_t fnCallback, uint64_t* userOrigVar);

	uint32_t* FindEatFunction();
	uint32_t* FindEatFunctionInModule() const;
	uint64_t FindModule();

	const uint16_t m_trampolineSize = 32;

	std::wstring m_moduleName;
	std::string m_apiName;

	uint64_t m_fnCallback;
	uint64_t m_origFunc;
	uint64_t* m_userOrigVar;

	// only used if EAT offset points >= 2GB
	RangeAllocator m_allocator;
	uint64_t m_trampoline;

	uint64_t m_moduleBase;
};
}