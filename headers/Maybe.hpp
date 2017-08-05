//
// Created by steve on 6/25/17.
//
#ifndef POLYHOOK_2_MONAD_HPP
#define POLYHOOK_2_MONAD_HPP

#include "headers/Enums.hpp"

#include <iostream>
#include <cassert>

namespace PLH {
/**An object that might contain a type T (the value), othewise
 * it will contain a type E (the error). This implementation
 * uses a boost variant for simplicity. If boost is not wanted
 * the same can be accomplished using in-place-new, and a buffer
 * that uses std::aligned_storage.**/

/**A special error type that can be used to attach a level of error to
 * an error message**/
struct ErrorSeverityMsg
{
    ErrorSeverityMsg()
    {
        m_severity = ErrorSeverity::Ok;
        m_errorMsg = "default initialized";
    }

    ErrorSeverityMsg(const ErrorSeverity level, const std::string& msg)
    {
        m_severity = level;
        m_errorMsg = msg;
    }

    ErrorSeverityMsg(const ErrorSeverity level, std::string&& msg)
    {
        m_severity = level;
        m_errorMsg = std::move(msg);
    }

    /**Used by function_assert. Default construct given only string**/
    ErrorSeverityMsg(const std::string& msg)
    {
        m_severity = ErrorSeverity::Critical;
        m_errorMsg = msg;
    }

    /**Used by function_assert. Default construct given only string**/
    ErrorSeverityMsg(std::string&& msg)
    {
        m_severity = ErrorSeverity::Critical;
        m_errorMsg = std::move(msg);
    }

    ErrorSeverity m_severity;
    std::string m_errorMsg;
};

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

template<typename T, typename EType = std::string>
class Maybe
{
public:
    Maybe() : m_error(ExplicitMaybeError<EType>(EType())),
              m_isError(true) {

    }

    Maybe(const ExplicitMaybeError<EType>& error) : m_error(error),
                                                    m_isError(true) {

    }

    Maybe(ExplicitMaybeError<EType>&& error) : m_error(std::move(error)),
                                               m_isError(true) {

    }

    Maybe(const T& value) : m_error(ExplicitMaybeError<EType>(EType())),
                            m_isError(false) {
        new(m_content) T(value);
    }

    Maybe(T&& value) : m_error(ExplicitMaybeError<EType>(EType())),
                       m_isError(false) {
        new(m_content) T(std::move(value));
    }

    /** const lvalue overload, copies content. Multiple visitation is
     * allowed. Not safe to call non-const member functions on T**/
    const T unwrap() const& {
        assert(isOk());
        return *reinterpret_cast<const T*>(m_content);
    }

    /** lvalue overload, ref to content. Multiple mutable visiation
     * is allowed. May call non-const member functions on T**/
    T& unwrap() &{
        assert(isOk());
        return *reinterpret_cast<T*>(m_content);
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

#define function_fail(...) OVERLOADED_MACRO(function_fail, __VA_ARGS__)
#define function_assert(...) OVERLOADED_MACRO(function_assert, __VA_ARGS__)

#define function_fail1(error) return PLH::ExplicitMaybeError<std::string>(error);

#define function_fail2(level, error) return PLH::ExplicitMaybeError<PLH::ErrorSeverityMsg>(PLH::ErrorSeverityMsg(level, error));

// assert in debug, fail return in release. Stronger runtime guards
#define function_assert1(expr) \
    if (!(expr)) {            \
    assert(expr);\
    return PLH::ExplicitMaybeError<std::string>("assertion failed: " #expr); \
    }

#define function_assert2(level, expr) \
    if (!(expr)) {            \
    assert(expr);\
    return PLH::ExplicitMaybeError<PLH::ErrorSeverityMsg>(PLH::ErrorSeverityMsg(level, "assertion failed: " #expr)); \
    }
#endif //POLYHOOK_2_MONAD_HPP
