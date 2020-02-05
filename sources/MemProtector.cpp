#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Enums.hpp"

#include <windows.h>

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<PLH::ProtFlag>(
		static_cast<std::uint8_t>(lhs) |
		static_cast<std::uint8_t>(rhs));
}

bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<std::uint8_t>(lhs) &
		static_cast<std::uint8_t>(rhs);
}

std::ostream& operator<<(std::ostream& os, const PLH::ProtFlag flags) {
	if (flags == PLH::ProtFlag::UNSET) {
		os << "UNSET";
		return os;
	}

	if (flags & PLH::ProtFlag::X)
		os << "x";
	else
		os << "-";

	if (flags & PLH::ProtFlag::R)
		os << "r";
	else
		os << "-";

	if (flags & PLH::ProtFlag::W)
		os << "w";
	else
		os << "-";

	if (flags & PLH::ProtFlag::NONE)
		os << "n";
	else
		os << "-";

	if (flags & PLH::ProtFlag::P)
		os << " private";
	else if (flags & PLH::ProtFlag::S)
		os << " shared";
	return os;
}

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = 0;
	if (flags == PLH::ProtFlag::X)
		NativeFlag = PAGE_EXECUTE;

	if (flags == PLH::ProtFlag::R)
		NativeFlag = PAGE_READONLY;

	if (flags == PLH::ProtFlag::W || (flags == (PLH::ProtFlag::R | PLH::ProtFlag::W)))
		NativeFlag = PAGE_READWRITE;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::R))
		NativeFlag = PAGE_EXECUTE_READ;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_READWRITE;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::R) && (flags & PLH::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_READWRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PAGE_NOACCESS;
	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::UNSET;
	switch (prot) {
	case PAGE_EXECUTE:
		flags = flags | PLH::ProtFlag::X;
		break;
	case PAGE_READONLY:
		flags = flags | PLH::ProtFlag::R;
		break;
	case PAGE_READWRITE:
		flags = flags | PLH::ProtFlag::W;
		flags = flags | PLH::ProtFlag::R;
		break;
	case PAGE_EXECUTE_READWRITE:
		flags = flags | PLH::ProtFlag::X;
		flags = flags | PLH::ProtFlag::R;
		flags = flags | PLH::ProtFlag::W;
		break;
	case PAGE_EXECUTE_READ:
		flags = flags | PLH::ProtFlag::X;
		flags = flags | PLH::ProtFlag::R;
		break;
	case PAGE_NOACCESS:
		flags = flags | PLH::ProtFlag::NONE;
		break;
	}
	return flags;
}
