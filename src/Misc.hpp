//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MISC_HPP
#define POLYHOOK_2_0_MISC_HPP
#include <stdexcept>
namespace PLH
{
    enum class Platform
    {
        WIN,
        UNIX
    };

    class NotImplementedException : public std::logic_error
    {
    public:
        NotImplementedException() : std::logic_error("Function not implemented")
        {

        }
    };
}
#endif //POLYHOOK_2_0_MISC_HPP
