//
// Created by steve on 4/20/17.
//

#pragma once

#include "polyhook2/PolyHookOs.hpp"

namespace PLH {

enum class HookType {
    Detour,
    VEHHOOK,
    VTableSwap,
    IAT,
    EAT,
    UNKNOWN
};



/* Used by detours class only. This doesn't live in instruction because it
 * only makes sense for specific jump instructions (perhaps re-factor instruction
 * to store inst. specific stuff when needed?). There are two classes of information for jumps
 * 1) how displacement is encoded, either relative to I.P. or Absolute
 * 2) where the jmp points, either absolutely to the destination or to a memory loc. that then points to the final dest.
 *
 * The first information is stored internal to the PLH::Instruction object. The second is this enum class that you
 * tack on via a pair or tuple when you need to transfer that knowledge.*/
enum class JmpType {
    Absolute,
    Indirect
};

enum class Mode {
    x86,
    x64
};

enum class ErrorLevel {
    INFO,
    WARN,
    SEV,
    NONE
};

//unsafe enum by design to allow binary OR
enum class ProtFlag : uint8_t {
    UNSET = 0, // Value means this give no information about protection state (un-read)
    X = 1 << 1,
    R = 1 << 2,
    W = 1 << 3,
    S = 1 << 4,
    P = 1 << 5,
    NONE = 1 << 6, //The value equaling the linux flag PROT_UNSET (read the prot, and the prot is unset)
    RWX = R | W | X
};

inline ProtFlag operator|(const ProtFlag lhs, const ProtFlag rhs) {
    using underlying = std::underlying_type<ProtFlag>::type;
    return static_cast<ProtFlag> (
        static_cast<underlying>(lhs) |
        static_cast<underlying>(rhs)
    );
}

inline bool operator&(const ProtFlag lhs, const ProtFlag rhs) {
    using underlying = std::underlying_type_t<ProtFlag>;
    return static_cast<underlying>(lhs) &
           static_cast<underlying>(rhs);
}

#ifdef PLH_DIAGNOSTICS
enum class Diagnostic : uint32_t {
    None  = 0,
    TranslatedInstructions = 1 << 0,
    FixedCallToRoutineReadingSP = 1 << 1, // #215
    FixedInlineCallToReadSP = 1 << 2, // #217
};
// Bitwise operators
inline Diagnostic operator|(const uint32_t flags, const Diagnostic diagnostic) {
    return static_cast<Diagnostic>(flags | static_cast<uint32_t>(diagnostic));
}
inline Diagnostic operator&(const uint32_t flags, const Diagnostic diagnostic) {
    return static_cast<Diagnostic>(flags & static_cast<uint32_t>(diagnostic));
}
#endif

}
