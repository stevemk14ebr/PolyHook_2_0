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

class VTableSwapHook : public PLH::IHook {
public:
	VTableSwapHook(const uint64_t Class, const VFuncMap& redirectMap);
	VTableSwapHook(const char* Class, const VFuncMap& redirectMap);
	virtual ~VTableSwapHook() = default;

	const VFuncMap& getOriginals() const;

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
	bool m_Hooked;
};


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

namespace detail {

	// helper function to convert sequence of VFunc structs into a VFuncMap
	// using recursive template definition
	inline PLH::VFuncMap make_vfunc_map()
	{
		return PLH::VFuncMap{ };
	};

	template<uint16_t I, typename FuncPtr, typename ... VFuncTypes>
	inline PLH::VFuncMap make_vfunc_map(VFunc<I, FuncPtr> vfunc, VFuncTypes ... vfuncs)
	{
		PLH::VFuncMap map{ {I, reinterpret_cast<uint64_t>(vfunc.func)} };
		map.merge(make_vfunc_map(vfuncs ...));
		return map;
	};

}

template<class ClassType, typename ... VFuncTypes>
class VTableSwapHook2 : private VTableSwapHook {
public:
	VTableSwapHook2(ClassType* instance, VFuncTypes ... newFuncs)
		: PLH::VTableSwapHook((char*)instance, detail::make_vfunc_map(newFuncs ...))
	{
		if (!hook())
			throw std::runtime_error(std::string("failed to hook ") + typeid(ClassType).name());
	};

	template<typename VFuncType, typename ... Args>
	auto origFunc(Args&& ... args) {
		auto func = reinterpret_cast<typename VFuncType::func_type>(getOriginals().at(VFuncType::func_index));
		if (func == nullptr)
			throw std::runtime_error("original virtual function pointer is null");
		return func(std::forward<Args>(args) ...);
	};

	virtual ~VTableSwapHook2()
	{
		unHook();
	}
};

}
#endif