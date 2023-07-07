#include "polyhook2/IHook.hpp"
#include "polyhook2/Detour/NatDetour.hpp"

#include <cstdarg>
uint64_t hookPrintfTramp = NULL;
NOINLINE int __cdecl h_hookPrintf(const char* format, ...) {
	char buffer[512];
	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);

	return PLH::FnCast(hookPrintfTramp, &printf)("INTERCEPTED YO:%s", buffer);
}

int main()
{
	PLH::NatDetour detour = PLH::NatDetour((uint64_t)&printf, (uint64_t)h_hookPrintf, &hookPrintfTramp);
	detour.hook();

	printf("%s %f\n", "hi", .5f);
	detour.unHook();
	return 0;
}