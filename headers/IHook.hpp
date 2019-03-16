//
// Created by steve on 4/2/17.
//

#ifndef POLYHOOK_2_0_IHOOK_HPP
#define POLYHOOK_2_0_IHOOK_HPP

#include "headers/ADisassembler.hpp"
#include "headers/Enums.hpp"

#if defined(__GNUC__) || defined(__GNUG__)|| defined(__clang__)
#define NOINLINE __attribute__((noinline))
#define NAKED __attribute__((naked))
#define OPTS_OFF _Pragma("GCC push_options") \
_Pragma("GCC optimize (\"O0\")")
#define OPTS_ON #pragma GCC pop_options
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#define NAKED __declspec(naked)
#define OPTS_OFF __pragma(optimize("", off))
#define OPTS_ON __pragma(optimize("", on))
#endif

namespace PLH {
class IHook {
public:
	virtual ~IHook() = default;
	
	virtual bool hook() = 0;
	virtual bool unHook() = 0;
	virtual HookType getType() const = 0;
};
}
#endif //POLYHOOK_2_0_IHOOK_HPP
