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
}