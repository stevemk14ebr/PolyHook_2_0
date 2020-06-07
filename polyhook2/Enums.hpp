//
// Created by steve on 4/20/17.
//

#ifndef POLYHOOK_2_0_ENUMS_HPP
#define POLYHOOK_2_0_ENUMS_HPP

#include <string>
#include <inttypes.h>

namespace PLH {

enum class HookType {
	Detour,
	VEHHOOK,
	VTableSwap,
	IAT,
	EAT,
	UNKNOWN
};


//unsafe enum by design to allow binary OR
enum ProtFlag : std::uint8_t {
	UNSET = 0, // Value means this give no information about protection state (un-read)
	X = 1 << 1,
	R = 1 << 2,
	W = 1 << 3,
	S = 1 << 4,
	P = 1 << 5,
	NONE = 1 << 6 //The value equaling the linux flag PROT_UNSET (read the prot, and the prot is unset)
};

/* Used by detours class only. This doesn't live in instruction because it
 * only makes sense for specific jump instructions (perhaps re-factor instruction
 * to store inst. specific stuff when needed?). There are two classes of information for jumps
 * 1) how displacement is encoded, either relative to I.P. or Absolute
 * 2) where the jmp points, either absolutely to the destination or to a memory loc. that then points to the final dest.
 *
 * The first information is stored internal to the PLH::Instruction object. The second is this enum class that you
 * tack on via a pair or tuple when you need to tranfer that knowledge.*/
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
}
#endif //POLYHOOK_2_0_ENUMS_HPP
