//
// Created by steve on 6/25/17.
//

#ifndef POLYHOOK_2_MONAD_HPP
#define POLYHOOK_2_MONAD_HPP

#include <iostream>

namespace PLH {
/**An object that might contain a type T (the value), othewise
 * it will contain a type E (the error). This implementation
 * uses a boost variant for simplicity. If boost is not wanted
 * the same can be accomplished using in-place-new, and a buffer
 * that uses std::aligned_storage.**/

/*A container for the error type to allow returning from a function. This should
 * definitely call std::decay, but i don't use char* or array types so no*/
template<typename E>
struct ExplicitMaybeError
{
    explicit ExplicitMaybeError(E&& error) : errorValue(std::forward<E>(error)) {
    }

    E error() {
        return errorValue;
    }

private:
    E errorValue;
};

template<typename T>
class Maybe
{
public:
    typedef std::string EType;

    Maybe() : m_error(ExplicitMaybeError<EType>("")),
              m_isError(true) {

    }

    Maybe(const ExplicitMaybeError<EType>& error) : m_error(error),
                                                    m_isError(true) {

    }

    Maybe(ExplicitMaybeError<EType>&& error) : m_error(std::move(error)),
                                               m_isError(true) {

    }

    Maybe(const T& value) : m_error(ExplicitMaybeError<EType>("")),
                            m_isError(false) {
        new(m_content) T(value);
    }

    Maybe(T&& value) : m_error(ExplicitMaybeError<EType>("")),
                       m_isError(false) {
        new(m_content) T(std::move(value));
    }

    /** lvalue overload, copies content. Multiple visitation is
     * allowed.**/
    T unwrap() const& {
        assert(isOk());
        return *reinterpret_cast<const T*>(m_content);
    }

    /** rvalue overload, moves content. Multiple visitation is
     * NOT allowed, and if you call this more than once you
     * will receive garbage data (this is undefined behavior)**/
    T&& unwrap()&& {
        assert(isOk());
        return std::move(*reinterpret_cast<T*>(m_content));
    }

    EType unwrapError() {
        assert(!isOk());
        return m_error.error();
    }

    bool isOk() const {
        return !m_isError;
    }

    operator bool() const {
        return isOk();
    }

private:
    typename std::aligned_storage<sizeof(T), alignof(T)>::type m_content[1];
    ExplicitMaybeError<EType> m_error;
    bool m_isError;
};
}
#define function_fail(error) return PLH::ExplicitMaybeError<std::string>(error);

#endif //POLYHOOK_2_MONAD_HPP
