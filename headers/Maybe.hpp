//
// Created by steve on 6/25/17.
//

#ifndef POLYHOOK_2_MONAD_HPP
#define POLYHOOK_2_MONAD_HPP

#include <boost/variant.hpp>

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

    Maybe(const ExplicitMaybeError<EType>& error) : content(error) {

    }

    Maybe(ExplicitMaybeError<EType>&& error) : content(std::move(error)) {

    }

    Maybe(const T& value) : content(value){

    }

    Maybe(T&& value) : content(std::move(value)) {

    }

    T unwrap() {
        assert(isOk());
        return boost::get<T>(content);
    }

    EType unwrapError() {
        assert(!isOk());
        return boost::get<ExplicitMaybeError<EType>>(content).error();
    }

    bool isOk() {
        return content.which() == 0;
    }

    operator bool()
    {
        return isOk();
    }
private:
    /*TODO: replace with std::variant when it is available. Or alternatively use std::aligned_storage + in-place new*/
    boost::variant<T, ExplicitMaybeError<EType>> content;
};
}
#define function_fail(error) return ExplicitMaybeError<std::string>(error);

#endif //POLYHOOK_2_MONAD_HPP
