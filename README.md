# PolyHook 2.0
C++17, x86/x64 Hooking Libary v2.0

Article 1: https://www.codeproject.com/articles/1100579/polyhook-the-cplusplus-x-x-hooking-library

Article 2: https://www.codeproject.com/Articles/1252212/PolyHook-2-Cplusplus17-x86-x64-Hooking-Library

# Build
```
git clone --recursive https://github.com/stevemk14ebr/PolyHook_2_0.git
cd PolyHook_2_0
git submodule update --init --recursive
```
Then run buildcapstone.bat and open this in VS2017 now that it has cmake support. By default buildcapstone will only include x86 architectures, to build capstone with all of them use --full-capstone command line arg. Instead of using VS 2017 you can instead generate a cmake project with 
```cmake -G```. But I recommend VS2017 very much.

You can build 3 different things. By default an executable is built and the unit tests are run. You can also build as a library by setting the ```BUILD_DLL``` option in CMakeLists.txt. If you choose to build as a library you can build it for static linking using the ```BUILD_STATIC``` option. I've setup an example project to show how to use this as a static library. You should clear your cmake cache between changing these options. The dll is built with the cmake option to export all symbols. This is different from the typical windows DLL where things are manually exported via declspec(dllexport), instead it behaves how linux dlls do with all symbols exported by default. This style should make it easier to maintain the code, the downside is there are many exports but i don't care.

Read the tests for docs for now until i write some. They are extensive

# Features
1) Inline hook (x86/x64 Detour)
    - Places a jmp to a callback at the prologue, and then allocates a trampoline to continue execution of the original function
    - Operates entirely on an intermediate instruction object, disassembler engine is swappable, capstone included by default
    - Follows already hooked functions
    - Resolves indirect calls such as through the iat and hooks underlying function
    - Relocates prologue and resolves all position dependent code
      - Branches into overwritten section are resolved to the new moved location
      - Jmps from moved prologue back to original section are resolved through a jmp table
      - Relocations inside the moved section are resolved (not using relocation table, disassembles using engine)
    - x64 trampoline is not restricted to +- 2GB, can be anywhere, avoids shadow space + no registers spoiled
    - If inline hook fails at an intermediate step the original function will not be malformed. All writes are batched until after we know later steps succeed.

2) Virtual Function Swap (VFuncSwap)
    * Swaps the pointers at given indexs in a C++ VTable to point to a callbacks
3) Virtual Table Swap (VTableSwap)
    * Performs a deep copy on a c++ VTable and replaces the pointer to the table with the newly allocated copy. Then swaps the pointer entries in the copy to point to callbacks
4) Software Breakpoint Hook (BreakpointHook)
    * Overwrites the first byte of a function with 0xCC and calls the callback in the exception handler. Provides the user with an automatic method to restore the original overwritten byte
5) Hardware Breakpoint Hook (HWBreakpointHook)
   * Sets the debug registers of the CPU to add a HW execution BP for the calling thread. The callback is called in the exception handler. Remember HW BP's are per thread, calling thread determines which thread bp is for
6) Import Address Table Hook (IatHook)
    * Resolves loaded modules through PEB, finds IAT, then swaps the thunk pointer to the callback. 
7) Export Address Table Hook (EatHook)
    * Resolves loaded modules through PEB, finds EAT, then swaps pointer to export to the callback.
    
# Extras
- THOROUGHLY unit tested, hundreds of tests, using the fantastic library Catch
- Fully wrapped capstone engine to emit instruction objects. The decompiler engine also tracks jmp and call destinations and builds a map of the distination to the sources, this allows the sort of logic you see in a debugger with the line pointing to the destination of the jmp. Capstone branch encoding features upstreamed to next and current submodule tagged to next
- Fully wrapped VirtualProtect into an OS agnostic call. Linux implementation is in the git history and will be exposed later once stable and more complete

# Notes
- Breakpoint tests must not be run under a debugger. They are commented out by default now.

# Future
Linux support

# Donate
Running Total: $40

[![Support via PayPal](https://cdn.rawgit.com/twolfson/paypal-github-button/1.0.0/dist/button.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=M2K8DQUNDUGMW&lc=US&item_name=PolyHook%20Donation&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

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
