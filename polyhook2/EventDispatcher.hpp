#pragma once
#include <functional>
#include <vector>

namespace PLH {
template<typename T>
class EventDispatcher
{
public:
	typedef std::function<T> Event;
	void operator+=(const Event& event);

	template<typename... Args>
	typename Event::result_type Invoke(Args&& ...Params)
	{
		assert(m_Event);
		return m_Event(std::forward<Args>(Params)...);
	}

	operator bool() const
	{
		return m_Event != nullptr;
	}
private:
	Event m_Event;
};

template<typename T>
void EventDispatcher<T>::operator+=(const Event& event)
{
	m_Event = event;
}
}