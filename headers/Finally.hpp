//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_FINALLY_HPP
#define POLYHOOK_2_FINALLY_HPP

#include <type_traits>
#include <utility>

namespace PLH {

//Java did one thing right.
template<typename Lambda>
class FinallyClass
{
public:
    FinallyClass(Lambda&& event) : m_lambda(std::move(event)) {
    }

    FinallyClass(const Lambda& event) : m_lambda(event) {
    }

    ~FinallyClass() {
        m_lambda();
    }

private:
    Lambda m_lambda;
};

template<typename Event>
FinallyClass<typename std::decay<Event>::type> finally(Event&& event) {
    return FinallyClass<typename std::decay<Event>::type>(std::forward<typename std::decay<Event>::type>(event));
}
}
#endif //POLYHOOK_2_FINALLY_HPP
