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
enum class ProtFlag : uint8_t {
	NONE = 0x00,
	R = 0x01,
	W = 0x02,
	X = 0x04
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
	SEV
};
}
#endif //POLYHOOK_2_0_ENUMS_HPP
