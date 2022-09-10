#pragma once

#include "polyhook2/PolyHookOs.hpp"

#ifdef POLYHOOK2_ARCH_X64
#include "polyhook2/Detour/x64Detour.hpp"
#else
#include "polyhook2/Detour/x86Detour.hpp"
#endif

namespace PLH {
#ifdef POLYHOOK2_ARCH_X64
	using NatDetour = x64Detour;
#else
	using NatDetour = x86Detour;
#endif
}