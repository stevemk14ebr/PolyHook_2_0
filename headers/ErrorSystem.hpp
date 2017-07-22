//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_ERRORSYSTEM_HPP
#define POLYHOOK_2_0_ERRORSYSTEM_HPP

#include <functional>
#include <vector>
#include <string>

namespace PLH {
class Message
{
public:
    Message(const std::string msg) {
        m_Msg = msg;
    }

    std::string getMessage() const {
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
    void invoke(Args&& ...params) {
        for (auto&& event : m_Events) {
            event(std::forward<Args>(params)...);
        }
    }

private:
    std::vector<Event> m_Events;
};

template<typename T>
void EventDispatcher<T>::operator+=(const Event& event) {
    m_Events.push_back(event);
}

template<typename T>
EventDispatcher<T> EventDispatcher<T>::operator--(int) {
    EventDispatcher<T> tmp(*this);
    if (m_Events.size() > 0)
        m_Events.pop_back();
    return tmp;
}

//Should be implemented when a process can be "errant" or "may throw errors"
class Errant
{
public:
    typedef PLH::EventDispatcher<void(const PLH::Message&)> tErrorHandler;

    virtual tErrorHandler& onError() {
        return m_ErrorCallback;
    }

    virtual void sendError(std::string msg) {
        m_ErrorCallback.invoke(msg);
    }

protected:

    tErrorHandler m_ErrorCallback;
};
}
#endif //POLYHOOK_2_0_ERRORSYSTEM_HPP
