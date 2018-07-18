# PolyHook 2.0
C+17, x86/x64 Hooking Libary v2.0

# Build
```
git clone --recursive https://github.com/stevemk14ebr/PolyHook_2_0.git
git submodule update --init --recursive
```
Then run buildcapstone.bat and open this in VS2017 now that it has cmake support. Or generate a cmake project with 
```cmake -G```. I recommend VS2017 very much.

Read the tests for docs for now until i write some. They are extensive

# Features
1) Inline hook (x86/x64 Detour)
    - Places a jmp to a callback at the prologue, and then allocates a trampoline to continue execution of the original function
    - Operates entirely on an intermediate instruction object, disassembler engine is swappable, capstone included by default
    - Follows already hooked functions
    - Resolves indirect calls such as through the iat and hooks underlying function
    - Relocates prologue and resolves all position dependent code
      - Branches of into overwritten section are resolved
      - Jmps from moved prologue back to original section are resolved
      - Relocations inside the moved section are resolved
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
    
# Extras
- THOROUGHLY unit tested, hundreds of tests, using the fantastic library Catch
- Fully wrapped capstone engine to emit instruction objects. Capstone branch encoding features upstreamed to next and current submodule tagged to next
- Fully wrapped VirtualProtect into an OS agnostic call. Linux implementation is in the git history and will be exposed later once stable and more complete

# Notes
- Breakpoint tests must not be run under a debugger. They are commented out by default now.

# Future
Linux support

# Donate
[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)]
https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=M2K8DQUNDUGMW&lc=US&item_name=PolyHook%20Donation&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted

# License
MIT - Please consider donating
