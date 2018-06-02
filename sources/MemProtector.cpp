#include "headers/MemProtector.hpp"
#include "headers/Enums.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<PLH::ProtFlag >(
		static_cast<std::uint8_t>(lhs) |
		static_cast<std::uint8_t>(rhs));
}

bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs) {
	return static_cast<std::uint8_t>(lhs) &
		static_cast<std::uint8_t>(rhs);
}

std::string PLH::ProtFlagToString(PLH::ProtFlag flags) {
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

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = 0;
	if (flags == PLH::ProtFlag::X)
		NativeFlag = PAGE_EXECUTE;

	if (flags == PLH::ProtFlag::R)
		NativeFlag = PAGE_READONLY;

	if (flags == PLH::ProtFlag::W)
		NativeFlag = PAGE_WRITECOPY;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::R))
		NativeFlag = PAGE_EXECUTE_READ;

	if ((flags & PLH::ProtFlag::X) && (flags & PLH::ProtFlag::W))
		NativeFlag = PAGE_EXECUTE_WRITECOPY;

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
	case PAGE_WRITECOPY:
		flags = flags | PLH::ProtFlag::W;
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
	case PAGE_EXECUTE_WRITECOPY:
		flags = flags | PLH::ProtFlag::X;
		flags = flags | PLH::ProtFlag::W;
		break;
	case PAGE_NOACCESS:
		flags = flags | PLH::ProtFlag::NONE;
		break;
	}
	return flags;
}