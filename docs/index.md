# PolyHook2 Documentation
I reserve the right to completely change any interface at any time. This documentation is an incomplete work in progress (consider helping!).

This library is object oriented in its design. All hooking methods supported derive from the base class ```IHook```. This base class is non-copyable, it may only be moved as it only ever makes sense to have a single object controlling a hook. The virtual methods ```hook()```, ```unhook```, and ```getType``` are provided. The ```hook``` and ```unhook``` methods will commit or decommit a hook depending on whatever implementation for the hook type was used. For example for detours (aka inline hooks) ```hook``` will overwrite the assembly of the hooked function to insert the appropriate jumps to a callback and create a trampoline. Inversely, ```unhook``` will restore the overwritten assembly and delete the trampoline. The ```getType``` method is used to retrieve the implementation type of the derived class that the ```IHook``` is the type of, this is used in place of RTTI in order to improve speed and increase simplicity. Do not call ```unhook``` before ```hook``` is called, this will produce undefined behavior or crash. All derived hook type are initialized via their constructor with whatever arguments are required for that method, the constructor will never actually commit the hook, that is only ever done by the ```hook``` method, this is done to support lazy initialzation. Instances of the ```IHook``` method must stay in scope while the hook is in place, in some cases the derived class destructor will invoke ```unhook``` and decommit the hook, in other cases it will produce undefined behavior if a hook is not decommitted before the destructor of the ```IHook``` instance is invoked. It is usually a good idea to wrap an ```IHook``` instance into either a ```std::shared_ptr``` or ```std::unique_ptr```. Memory address's are always represented as ```uint64_t``` to support cross architecture hooking. For convienience ```char*``` overloads exist in many cases, but uint64_t variants should be prefered. As a user of this library always prefer ```uint64_t``` to ```char*``` and either over ```void*``` which should never be used in C++ code.

For cross architecture support the ```IHook``` class derives from ```MemAccessor```. This class provides routines which implement memory reading and writing. There are two variants of read and write each, a safe one and an unsafe one. The unsafe variants are used by libraries in situations when the memory accessed is controlled by the library and expected to be valid. The safe variants must provide safety such that when the library calls them on memory which may be invalid, innaccessible, or wrould otherwise fault, that the faults are caught and transparently handled. These interfaces exist so that they can be overridden to, for example, read 64 bit addresses when compiling/hooking in 32bit mode. An example implementation of cross architecture hooking is described in the blog: https://www.fireeye.com/blog/threat-research/2020/11/wow64-subsystem-internals-and-hooking-techniques.html. Most of the time this functionality will not be useful or needed, but it does exist.

## Supported Hooking Methods

* x86/x64 Detours (inline hooks when typedef is known statically)
* Runtime x86/x64 Detours (inline hooks when typedef is not known statically)
* INT3 + Vectored Exception Handling
* HWBP + Vectored Exception Handling
* Virtual Function Swap
* Virtual Table Swap
* Import Address Table Hook
* Export Address Table Hook

### x86/x64 Detours

This is the most complicated component of this library by far, I will not be explaining what inline hooks are, or how they work. I will first explain the interface this library exposes, and then from a very high level explain the implementation decisions this library chooses and how it varies from other libraries such a MSDetours. 

##### Interface

There are two overloads, a ```uint64_t``` and ```char*``` variant.
```
Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis)
Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis)
```

* fnAddress: The memory address of the function to hook.
* fnCallback: The memory address of the hook callback
* userTrampVar: A pointer to a ```uint64_t``` (_MUST_ be uint64_t), this store a function pointer to the trampoline created during hooking.
* dis: An instance of either ```ZydisDisassembler```. Must stay in scope for the duration the ```Detour``` is alive.

fnAddress is a function pointer. The library will inspect the assembly at this memory location and first determine if the provided function pointer is indirect and attempt to resolve the location of the true assembly body. For example in x64 release mode the vast majority of the time function pointers point to ```jmp``` instructions which go through multiple levels before finally hitting the implementation body. This occurs due to IAT resolution, linker optimizations, and other compiler internal layout reasons. If a function is already hooked with say an ```e9xxxxxxxx jmp <xxxxxxxx>``` Polyhook will follow the jmp and hook the handler that already exists. Complicated jmp types like ```mov rbx, xxxxxxxx; jmp rbx``` are not followed as the library does not track intermediate register or stack operations, only indirect memory or direct jmps are followed. If you have cases with indirection via registers like this you can handle this manually by resolving these sorts of prologues in user logic and then passing the real, final, function address to polyhook.

fnCallback: is a function pointer. The same jmp following logic that occurs to fnAddress also applies to this function pointer. Again this is a necessity due to compiler internals. The type definition of this function must match the exact type definition of the fnAddress. If you hook a function with the typdef ```void __stdcall foo(int a, float b)``` then fnCallback's typedef must be ```void __stdcall foo(int a, float b)```. If you do not obey this you will have possible stack corruption, invalid register stomping or other memory corruption errors including incorrect execution after the callback finishes. For C++ member functions remember that there is a hidden ```this``` parameter as the first argument which in assembly land will be in register ```ecx``` or ```rcx``` therefore your callback typedef must explicitly have the the ```this``` parameter specified ```void foo(MyClass* _this, int a, int b)```. 

Within the callback it is allowable to modify parameters, perform arbitrary logic, and potentially return spoofed return values. Care must be taken not to call any function which will call the original function again or stack exchaustion will occur. For example if you hook ```WriteFile``` which when hooked dispatches to the user callback ```hkWriteFile``` you may not call ```WriteFile``` or any api that would call it from within the callback or a cycle will be created that infinitely invokes the callback ```WriteFile -> hkWriteFile -> WriteFile -> hkWriteFile -> ad infinit```. To properly invoke the original function the trampoline exists. You may cast the variable ```userTrampVar``` to the typedef of the hooked function and then invoke it with the arguments from the callback. It's simplest to show an example:

```
uint64_t oCreateMutexExA = 0;
HANDLE
WINAPI
hCreateMutexExA(
	_In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_opt_ LPCSTR lpName,
	_In_ DWORD dwFlags,
	_In_ DWORD dwDesiredAccess
) {
	printf("kernel32!CreateMutexExA  Name:%s",  lpName);
	return PLH::FnCast(oCreateMutexExA, &CreateMutexExA)(lpMutexAttributes, "fake name", dwFlags, dwDesiredAccess);
}

PLH::x64Detour detour((char*)&CreateMutexExA, (char*)&hCreateMutexExA, &oCreateMutexExA, dis);
detour.hook();
```

Notice the usage of ```PLH::FnCast```. This is a simple helper utility provided that uses a C++ template to do the function pointer cast in a clean way. You may choose to not use this if desired. The helper takes as first argument the trampoline pointer and then as second a pointer to the original function and casts the trampoline to the type of the original function pointer. It's also allowable to call the original function out of order in the callback, in order to inspect the return value and intercept it:

```
HANDLE
WINAPI
hCreateMutexExA(
	_In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_opt_ LPCSTR lpName,
	_In_ DWORD dwFlags,
	_In_ DWORD dwDesiredAccess
) {
	auto returnVal = PLH::FnCast(oCreateMutexExA, &CreateMutexExA)(lpMutexAttributes, "fake name", dwFlags, dwDesiredAccess);
	if (returnVal) {
     print("Return value is non-zero!");
     return 0; // spoof zero
  }
  return returnVal;
}
```

##### Implementation

This section will highlight some of the features you can expect from this implementation of detours (inline hooking), as well as a comparison to some other popular library implemntations. First, this impelementation follows jmps at the beginning of function pointers as highlighted earlier. To my knowledge Microsoft's detours is the only library i am personally aware of that takes this into consideration. The implementation choices there are hardcoded to expect particular patterns of jmp encodings however, which is dependant on particular code generation patterns likely common to the windows system. Second, this library uses trampolines to continue execution of the original function. Some libraries expect functions to be quickly unhooked, the original called, and then re-hooked. We do not have this concern however due to the trampoline. Using trampolines on x64 is tricky due to the restriction of it being within +-2Gb to fit within range of 32bit instructino displacement encodings. Microsoft chooses to dynamically allocate memory within this range and implements a custom allocator ontop of the windows one to enforce this guarantee. In my experience this is very delicate and _difficult_ to get correct, honestly props to microsoft for doing this in a way that appears to work and work well. This library however chooses to search for code caves within the allowable memory range and fill the cave with the tramoline code. This is adventageous because the code is spatially much closer, often times the trampoline or the hook jmp itself can just overwrite compiler padding bytes adjacent to the original function. However, it takes longer to perform this search in the way implemented in Polyhook as ReadVirtualMemory is simply called in a loop on potentially invalid memory which required N number of context switches + exception handling logic. This can be improved in time but it's my opinion that not maintaining a custom memory allocator is adventageous in the long term. Polyhook additionally takes special care not to spoil registers, stack, or any other memory regions as part of its control flow redirection. This vastly simplifies the backup-restore logic required for hooks as there simply is not anything to preserve since it was never spoiled. This is something that Detours also avoids, but other libraries, especially for x64 tend to spoil a register moving the destination to jmp to when dispatching to the callback. Not spoiling registers and stack values has the awesome secondary quality of allowing shellcodes and cross architecture jumps to be written. You could as a user give polyhook a mid-function pointer and tell it to hook the function and then point to shellcode as the user callback. The user callback shellcode would do all the mid-function hook things and as long as it was written correctly could inspect, read, and modify register values and then polyhook will generate a trampoline to continue execution of the function after the mid-function hook shellcode is done. This is a very powerful technique, and is almost required to implement hooks on say the wow64 layer. 

Finally, polyhook takes exceptional care to both handle the long tail of weird cases and for uncovered cases to fail gracefully. All hooking operations operate on a copied representation of the assembly, and then changes are only committed if all intermediate operations succeed. There is no transactional API, as internally polyhook itself is transaction. The ```hook``` methods will either work and return true, or fail and return false.


### Runtime x86/x64 Detours (inline hooks when typedef is not known statically)
Documentation TODO 

### INT3 + Vectored Exception Handling
Documentation TODO 

### HWBP + Vectored Exception Handling
Documentation TODO 

### Virtual Function Swap
Documentation TODO 

### Virtual Table Swap
Documentation TODO 

### Import Address Table Hook
Documentation TODO 

### Export Address Table Hook
Documentation TODO 

