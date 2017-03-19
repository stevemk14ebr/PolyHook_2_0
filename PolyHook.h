#ifndef POLYHOOK_2_0_POLYHOOK_H
#define POLYHOOK_2_0_POLYHOOK_H
#define DEBUG_MODE (0)
#define ARCH_WIN (0)
#define ARCH_LIN (1)
#define MODE_x64 (0)
#define MODE_x86 (1)

#include <string>
#include <functional>
#include <vector>

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

    class Message
    {
    public:
        Message(std::string& msg)
        {
            m_Msg = msg;
        }

        std::string GetMessage() const
        {
            return m_Msg;
        }
    private:
        std::string m_Msg;
    };

    template<typename T>
    class EventDispatcher
    {
    public:
        typedef std::function<T> Event;
        void operator+=(const Event& event);
        EventDispatcher<T> operator--(int);

        template<typename... Args>
        void Invoke(Args&& ...Params)
        {
            for (auto&& event : m_Events)
            {
                event(std::forward<Args>(Params)...);
            }
        }
    private:
        std::vector<Event> m_Events;
    };

    template<typename T>
    void EventDispatcher<T>::operator+=(const Event& event)
    {
        m_Events.push_back(event);
    }

    template<typename T>
    EventDispatcher<T> EventDispatcher<T>::operator--(int)
    {
        EventDispatcher<T> tmp(*this);
        if(m_Events.size() > 0)
            m_Events.pop_back();
        return tmp;
    }

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
