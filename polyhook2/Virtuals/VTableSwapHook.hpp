#ifndef POLYHOOK_2_0_VTBLSWAPHOOK_HPP
#define POLYHOOK_2_0_VTBLSWAPHOOK_HPP

#include <cassert>
#include <memory>
#include <map>

#include "polyhook2/IHook.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Misc.hpp"

namespace PLH {

typedef std::map<uint16_t, uint64_t> VFuncMap;

// storage class for address of a virtual function
// also stores the function pointer type and index number on the class level
template<uint16_t I, typename FuncPtr>
struct VFunc {
	VFunc() : func(nullptr) {};
	VFunc(FuncPtr f) : func(f) {};
	const FuncPtr func;
	static const uint16_t func_index;
	typedef FuncPtr func_type;
};

// definition of constant must reside outside class declaration
template<uint16_t I, typename FuncPtr> const uint16_t VFunc<I, FuncPtr>::func_index = I;

class VTableSwapHook : public PLH::IHook {
public:
	VTableSwapHook(const uint64_t Class);
	VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap);
	VTableSwapHook(const char* Class, const VFuncMap& redirectMap);

	template<uint16_t I, typename FuncPtr, typename ... VFuncTypes>
	VTableSwapHook(const uint64_t Class, VFunc<I, FuncPtr> vfunc, VFuncTypes ... vfuncs)
		: VTableSwapHook(Class, vfuncs ...)
	{
		m_redirectMap[I] = reinterpret_cast<uint64_t>(vfunc.func);
	};

	virtual ~VTableSwapHook() {
		if (m_hooked) {
			unHook();
		}
	}

	const VFuncMap& getOriginals() const;

	template<typename VFuncType, typename ... Args>
	auto origFunc(Args&& ... args) {
		// NOTE: could do extra type check if VFuncTypes were a template argument of the class
		// static_assert(std::disjunction_v<std::is_same<VFuncType, VFuncTypes> ...>);
		auto func = reinterpret_cast<typename VFuncType::func_type>(m_origVFuncs.at(VFuncType::func_index));
		return func(std::forward<Args>(args) ...);
	};

	virtual bool hook() override;
	virtual bool unHook() override;
	virtual HookType getType() const override {
		return HookType::VTableSwap;
	}
private:
	uint16_t countVFuncs();

	std::unique_ptr<uintptr_t[]> m_newVtable;
	uintptr_t* m_origVtable;

	uint64_t  m_class;

	uint16_t  m_vFuncCount;

	// index -> ptr val 
	VFuncMap m_redirectMap;
	VFuncMap m_origVFuncs;
};

}

#endif