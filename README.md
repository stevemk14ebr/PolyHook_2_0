# PolyHook 2.0
C++17, x86/x64 Hooking Libary v2.0

Article 1: https://www.codeproject.com/articles/1100579/polyhook-the-cplusplus-x-x-hooking-library

Article 2: https://www.codeproject.com/Articles/1252212/PolyHook-2-Cplusplus17-x86-x64-Hooking-Library

# Community
Ask for help, chat with others, talk to me here
* [Official Gitter Chat](https://gitter.im/PolyHook/Lobby)
* Please consider sponsoring my work by clicking sponsor up in the top right

# Packaging
PolyHook2 is available on vcpkg. Consider trying that installation method if you prefer. Just install vcpkg from microsofts directions: 

Commands: 
```
λ git clone https://github.com/Microsoft/vcpkg.git
λ cd vcpkg
λ .\bootstrap-vcpkg.bat -disableMetrics
λ (as admin) .\vcpkg integrate install
λ vcpkg.exe install polyhook2
```
You then simply include the polyhook headers, be sure to link the generated .lib.

# Build Manually
See: https://github.com/stevemk14ebr/PolyHook_2_0/pull/59#issuecomment-619223616
```
λ git clone --recursive https://github.com/stevemk14ebr/PolyHook_2_0.git
λ cd PolyHook_2_0
λ git submodule update --init --recursive
λ cmake -B"./_build" -DCMAKE_INSTALL_PREFIX="./_install/" -DPOLYHOOK_BUILD_SHARED_LIB=ON
λ cmake --build "./_build" --config Release --target INSTALL
```
I provide directions below for how to setup the visual studio cmake environment only. If you don't want to use visual studio that's fine, this is a standard cmake project and will build from command line just fine. 

### Visual Studio 2017/2019
clone the project and perform submodule init as above. Do not run the cmake commands, instead:

Open VS 2017, go to file->open->cmake.. this will load the project and start cmake generation. Next goto cmake->build all or cmake->build, you can also set a startup item and release mode to use the play button (do not use the install target). Capstone, Zydis, and asmjit are set to automatically build and link, you DO NOT need to build them seperately.

### Documentation
https://stevemk14ebr.github.io/PolyHook_2_0/ & Read the Tests!

I've setup an example project to show how to use this as a static library. You should clear your cmake cache between changing these options. The dll is built with the cmake option to export all symbols. This is different from the typical windows DLL where things are manually exported via declspec(dllexport), instead it behaves how linux dlls do with all symbols exported by default. This style should make it easier to maintain the code, the downside is there are many exports but i don't care.

# Features
0) Both capstone and zydis are supported as disassembly backends and are fully abstracted
1) Inline hook (x86/x64 Detour)
    - Places a jmp to a callback at the prologue, and then allocates a trampoline to continue execution of the original function
    - Operates entirely on an intermediate instruction object, disassembler engine is swappable, capstone included by default
    - Can JIT callback for when calling conv is unknown at compile time (see ILCallback.cpp)
    - Follows already hooked functions
    - Resolves indirect calls such as through the iat and hooks underlying function
    - Relocates prologue and resolves all position dependent code
      - Branches into overwritten section are resolved to the new moved location
      - Jmps from moved prologue back to original section are resolved through a jmp table
      - Relocations inside the moved section are resolved (not using relocation table, disassembles using engine)
    - x64 trampoline is not restricted to +- 2GB, can be anywhere, avoids shadow space + no registers spoiled
    - If inline hook fails at an intermediate step the original function will not be malformed. All writes are batched until after we know later steps succeed.
    
 2) Runtime Inline Hook
    - All the goodness of normal inline hooks, but JIT's a translation stub compatible with the given typedef and ABI. The translation stub will move arguments into a small struct, which is passed as pointer to a callback and allow the spoofing of return value. This allows tools to generate hook translation stubs at runtime, allowing for the full inline hooking of functions where the typedef is not known until runtime.

3) Virtual Function Swap (VFuncSwap)
    * Swaps the pointers at given indexs in a C++ VTable to point to a callbacks
4) Virtual Table Swap (VTableSwap)
    * Performs a deep copy on a c++ VTable and replaces the pointer to the table with the newly allocated copy. Then swaps the pointer entries in the copy to point to callbacks
5) Software Breakpoint Hook (BreakpointHook)
    * Overwrites the first byte of a function with 0xCC and calls the callback in the exception handler. Provides the user with an automatic method to restore the original overwritten byte
6) Hardware Breakpoint Hook (HWBreakpointHook)
   * Sets the debug registers of the CPU to add a HW execution BP for the calling thread. The callback is called in the exception handler. **Remember HW BP's are per thread, the thread calling hook() must be the same as the one that is being hooked. You may find a quick detour, then setting up the HWBP in the detour callback, then unhooking to be a useful construct.**
7) Import Address Table Hook (IatHook)
    * Resolves loaded modules through PEB, finds IAT, then swaps the thunk pointer to the callback. 
8) Export Address Table Hook (EatHook)
    * Resolves loaded modules through PEB, finds EAT, then swaps pointer to export to the callback. Since this is a 32bit offset we optionally allocate a trampoline stub to do the full transfer to callback if it's beyond 32bits.
    
# Extras
- THOROUGHLY unit tested, hundreds of tests, using the fantastic library Catch
- Fully wrapped capstone engine to emit instruction objects. The decompiler engine also tracks jmp and call destinations and builds a map of the distination to the sources, this allows the sort of logic you see in a debugger with the line pointing to the destination of the jmp. Capstone branch encoding features upstreamed to next and current submodule tagged to next
- Fully wrapped VirtualProtect into an OS agnostic call. Linux implementation is in the git history and will be exposed later once stable and more complete

# Notes
- Breakpoint tests must not be run under a debugger. They are commented out by default now.

# Future
Linux support

# License
MIT - Please consider donating

# Resource &/| references
evolution536, DarthTon, IChooseYou on Unknowncheats.me

@Ochii & https://www.unknowncheats.me/forum/c-and-c/50426-eat-hooking-dlls.html for EAT implementation

https://github.com/DarthTon/Blackbone

https://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra

https://wiki.osdev.org/CPU_Registers_x86#Debug_Registers

https://reverseengineering.stackexchange.com/questions/14992/what-are-the-vectored-continue-handlers

https://web.archive.org/web/20170126064234/https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/

https://github.com/odzhan/shellcode/blob/master/os/win/getapi/dynamic/getapi.c
