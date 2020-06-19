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
		return m_Event(std::forward<Args>(Params)...);
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