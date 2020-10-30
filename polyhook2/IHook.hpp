//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_IHOOK_HPP
#define POLYHOOK_2_0_IHOOK_HPP


#include "polyhook2/ADisassembler.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/MemAccessor.hpp"

#include <type_traits>
#include <tuple>
#include <utility>


#if defined(__clang__)
#define NOINLINE __attribute__((noinline))
#define PH_ATTR_NAKED __attribute__((naked))
#elif defined(__GNUC__) || defined(__GNUG__)
#define NOINLINE __attribute__((noinline))
#define PH_ATTR_NAKED __attribute__((naked))
#define OPTS_OFF _Pragma("GCC push_options") \
_Pragma("GCC optimize (\"O0\")")
#define OPTS_ON #pragma GCC pop_options
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#define PH_ATTR_NAKED __declspec(naked)
#define OPTS_OFF __pragma(optimize("", off))
#define OPTS_ON __pragma(optimize("", on))
#endif

#define PH_UNUSED(a) (void)a

namespace PLH {
class IHook : public MemAccessor {
public:
	IHook() {
		m_debugSet = false;
		m_hooked = false;
	}

	IHook(IHook&& other) = default; //move
	IHook& operator=(IHook&& other) = default;//move assignment
	IHook(const IHook& other) = delete; //copy
	IHook& operator=(const IHook& other) = delete; //copy assignment
	virtual ~IHook() = default;

	virtual bool hook() = 0;

	virtual bool unHook() = 0;

	// this is allowed to be nothing by default
	virtual bool reHook() {
		return true;
	}

	virtual HookType getType() const = 0;

	virtual void setDebug(const bool state) {
		m_debugSet = state;
	}

protected:
	bool m_debugSet;
	bool m_hooked;
};

//Thanks @_can1357 for help with this.
template<typename T, typename = void>
struct callback_type { using type = T; };

template<typename T>
using callback_type_t = typename callback_type<T>::type;

template<auto V>
using callback_type_v = typename callback_type<decltype(V)>::type;

#define MAKE_CALLBACK_IMPL(CCFROM, CCTO) template<typename F, typename Ret, typename... Args> \
auto make_callback(Ret(CCFROM*)(Args...), F&& f) \
{ \
    Ret(CCTO * fn)(Args...) = f; \
    return fn; \
} \
template<typename Ret, typename... Args> \
struct callback_type<Ret(CCFROM*)(Args...), void> \
{ \
    using type = Ret(CCTO*)(Args...); \
};

// switch to __VA_OPT__ when C++ 2a release. MSVC removes comma before empty __VA_ARGS__ as is.
// https://devblogs.microsoft.com/cppblog/msvc-preprocessor-progress-towards-conformance/
#define MAKE_CALLBACK_CLASS_IMPL(CCFROM, CCTO, ...) template<typename F, typename Ret, typename Class, typename... Args> \
auto make_callback(Ret(CCFROM Class::*)(Args...), F&& f) \
{ \
    Ret(CCTO * fn)(Class*, ## __VA_ARGS__, Args...) = f; \
    return fn; \
} \
template<typename Ret, typename Class, typename... Args> \
struct callback_type<Ret(CCFROM Class::*)(Args...), void> \
{ \
    using type = Ret(CCTO*)(Class*, ## __VA_ARGS__, Args...); \
};

#ifndef _WIN64 
MAKE_CALLBACK_IMPL(__stdcall, __stdcall)
MAKE_CALLBACK_CLASS_IMPL(__stdcall, __stdcall)

MAKE_CALLBACK_IMPL(__cdecl, __cdecl)
MAKE_CALLBACK_CLASS_IMPL(__cdecl, __cdecl)

MAKE_CALLBACK_IMPL(__thiscall, __thiscall)
MAKE_CALLBACK_CLASS_IMPL(__thiscall, __fastcall, char*)
#endif

MAKE_CALLBACK_IMPL(__fastcall, __fastcall)
MAKE_CALLBACK_CLASS_IMPL(_fastcall, __fastcall)

template <int I, class... Ts>
decltype(auto) get_pack_idx(Ts&&... ts) {
	return std::get<I>(std::forward_as_tuple(ts...));
}
}

/**
Creates a hook callback function pointer that matches the type of a given function definition. The name variable
will be a pointer to the function, and the variables _args... and name_t will be created to represent the original
arguments of the function and the type of the callback respectively.
**/
#define HOOK_CALLBACK(pType, name, body) typedef PLH::callback_type_t<decltype(pType)> ##name##_t; \
PLH::callback_type_t<decltype(pType)> name = PLH::make_callback(pType, [](auto... _args) body )

/**
When using the HOOK_CALLBACK macro this helper utility can be used to retreive one of the original
arguments by index. The type and value will exactly match that of the original function at that index.
for member functions this is essentially 1's indexed because first param is this*
**/
#define GET_ARG(idx) PLH::get_pack_idx<idx>(_args...)

#endif //POLYHOOK_2_0_IHOOK_HPP
