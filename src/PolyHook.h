#ifndef POLYHOOK_2_0_POLYHOOK_H
#define POLYHOOK_2_0_POLYHOOK_H

#define DEBUG_MODE (0)
#define ARCH_WIN (0)
#define ARCH_LIN (1)
#define MODE_x64 (0)
#define MODE_x86 (1)

#include <string>

#include "TestErrorSystem.hpp"
#include "ADisassembler.hpp"

namespace PLH
{
    enum class HookType
    {
        X86Detour,
        X64Detour,
        UNKNOWN
#if(ARCH_WIN)
        ,VFuncSwap,
		VFuncDetour,
		VTableSwap,
		IAT,
		VEH,
#endif
    };

    class IHook
    {
    public:
        IHook() = default;
        IHook(IHook&& other) = default; //move
        IHook& operator=(IHook&& other) = default;//move assignment
        IHook(const IHook& other) = delete; //copy
        IHook& operator=(const IHook& other) = delete; //copy assignment
        virtual ~IHook() = default;

        virtual bool Hook() = 0;
        virtual void UnHook() = 0;
        virtual HookType GetType() = 0;

        typedef PLH::EventDispatcher<void(const PLH::Message&)> tErrorHandler;

        virtual tErrorHandler& OnError()
        {
            return m_ErrorCallback;
        }
    protected:
        tErrorHandler m_ErrorCallback;
    };


}
#endif //POLYHOOK_2_0_POLYHOOK_H
