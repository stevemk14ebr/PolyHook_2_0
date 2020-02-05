// ExampleProject.cpp : Defines the entry point for the application.
//

#include "ExampleProject.h"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/Detour/x86Detour.hpp"

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

/** THIS EXAMPLE IS SETUP FOR x86. IT WILL CRASH IF YOU COMPILE IN x64**/
int main()
{
	// Switch modes for x64
	PLH::CapstoneDisassembler dis(PLH::Mode::x86);
	PLH::x86Detour detour((char*)&printf, (char*)&h_hookPrintf, &hookPrintfTramp, dis);
	detour.hook();

	printf("%s %f\n", "hi", .5f);
	detour.unHook();
	getchar();
	return 0;
}
