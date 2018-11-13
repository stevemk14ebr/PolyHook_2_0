//https://github.com/odzhan/shellcode/blob/master/os/win/getapi/dynamic/getapi.c
//https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/
#include <string>
#include <iostream>
#include <algorithm>

#include "headers/ErrorLog.hpp"
#include "headers/IHook.hpp"
#include "headers/MemProtector.hpp"
#include "headers/Misc.hpp"
#include "headers/PE/PEB.hpp"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

namespace PLH {
class IatHook : public IHook {
public:
	IatHook(const std::string& dllName, const std::string& apiName, const char* fnCallback, uint64_t* userOrigVar, const std::wstring& moduleName);
	IatHook(const std::string& dllName, const std::string& apiName, const uint64_t fnCallback, uint64_t* userOrigVar, const std::wstring& moduleName);
	virtual ~IatHook() = default;
	virtual bool hook() override;
	virtual bool unHook() override;
	virtual HookType getType() const override {
		return HookType::IAT;
	}
private:
	IMAGE_THUNK_DATA* FindIatThunk(const std::string& dllName, const std::string& apiName, const std::wstring moduleName = L"");
	IMAGE_THUNK_DATA* FindIatThunkInModule(void* moduleBase, const std::string& dllName, const std::string& apiName);

	std::string m_dllName;
	std::string m_apiName;
	std::wstring m_moduleName;

	uint64_t m_fnCallback;
	uint64_t m_origFunc;
	uint64_t* m_userOrigVar;

	bool m_hooked;
};
}