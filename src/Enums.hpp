//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_ENUMS_HPP
#define POLYHOOK_2_0_ENUMS_HPP
#include <string>
#include <inttypes.h>
namespace PLH
{
//unsafe enum by design to allow binary OR
    enum ProtFlag : std::uint8_t
    {
        UNSET = 0, //the value meaning no protection is set
        X = 1 << 1,
        R = 1 << 2,
        W = 1 << 3,
        S = 1 << 4,
        P = 1 << 5,
        NONE = 1 << 6 //The flag meaning PROT_UNSET
    };

    bool operator&(ProtFlag lhs, ProtFlag rhs)
    {
        return static_cast<std::uint8_t>(lhs) &
               static_cast<std::uint8_t>(rhs);
    }

    ProtFlag operator|(ProtFlag lhs, ProtFlag rhs)
    {
        return static_cast<ProtFlag >(
                static_cast<std::uint8_t>(lhs) |
                static_cast<std::uint8_t>(rhs));
    }

    std::string ProtFlagToString(PLH::ProtFlag flags)
    {
        std::string s = "";
        if (flags == PLH::ProtFlag::UNSET) {
            s += "UNSET";
            return s;
        }

        if (flags & PLH::ProtFlag::X)
            s += "x";
        else
            s += "-";

        if (flags & PLH::ProtFlag::R)
            s += "r";
        else
            s += "-";

        if (flags & PLH::ProtFlag::W)
            s += "w";
        else
            s += "-";

        if (flags & PLH::ProtFlag::NONE)
            s += "n";
        else
            s += "-";

        if (flags & PLH::ProtFlag::P)
            s += " private";
        else if (flags & PLH::ProtFlag::S)
            s += " shared";
        return s;
    }
}
#endif //POLYHOOK_2_0_ENUMS_HPP
