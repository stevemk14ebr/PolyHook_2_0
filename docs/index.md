# PolyHook2 Documentation
I reserved the right to completely change any interface at any time.

This library is object oriented in its design. All hooking methods supported derive from the base class ```IHook```. This base class is non-copyable, it may only be moved as it only ever makes sense to have a single object controlling a hook. The virtual methods ```hook()```, ```unhook```, and ```getType``` are provided. The ```hook``` and ```unhook``` methods will commit or decommit a hook depending on whatever implementation for the hook type was used. For example for detours (aka inline hooks) hook will overwrite the assembly of the hooked function to insert the appropriate jumps to a callback, while unhook will restore the overwritten assembly and delete the trampoline. The ```getType``` method is used to retrieve the implementation type of the derived class that the ```IHook``` is the type of, this is used in place of RTTI in order to improve speed and increase simplicity. Do not call ```unhook``` before ```hook``` is called, this will produced undefined behavior or crash. All derived hook type are initialized via their constructor with whatever arguments are required for that method, the constructor will never actually commit the hook, that is only ever done by the ```hook``` method. Instances of the ```IHook``` method must stay in scope while the hook is in place, in some cases the derived class destructor will invoke ```unhook``` and decommit the hook, in other cases it will produce undefined behavior if a hook is not decommitted before the destructor of the ```IHook``` instance is invoked. It is usually a good idea to wrap an ```IHook``` instance into either a ```std::shared_ptr``` or ```std::unique_ptr```.

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