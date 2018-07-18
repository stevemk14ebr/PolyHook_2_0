# PolyHook 2.0
C+11, x86/x64 Hooking Libary v2.0

# Build

```
cd capstone
mkdir build && mkdir build64
cd build
cmake .. -DCAPSTONE_BUILD_TESTS=OFF
cmake --build . --config Release
cmake --build . --config Debug

cd ../build64
cmake .. -DCAPSTONE_BUILD_TESTS=OFF -DCMAKE_GENERATOR_PLATFORM=x64
cmake --build . --config Release
cmake --build . --config Debug
```
#Features
1) Inline hook (x86/x64 Detour)
    - Places a jmp to a callback at the prologue, and the allocates a trampoline to continue execution of the original function
    - Follows already hooked functions
    - Resolves indirect calls such as through the iat and hooks underlying function
    - Relocates prologue and resolves all position dependent code
      - Branches of into overwritten section are resolved
      - Jmps from moved prologue back to original section are resolved
      - Relocations inside the moved section are resolved
    - x64 trampoline is not restricted to +- 2GB, can be anywhere, avoids shadow space + no registers spoiled
    - Disassembler engine is swappable, capstone included by default

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
    
# Extras
- Fully wrapped capstone engine to emit instruction objects. Capstone branch encoding features upstreamed to next and current submodule tagged to next

# Future
Linux support

# License
MIT - Please consider donating
