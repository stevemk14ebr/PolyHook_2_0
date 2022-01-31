#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

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

#if defined(POLYHOOK2_OS_WINDOWS)

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

#elif defined(POLYHOOK2_OS_LINUX)

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = PROT_NONE;
	if (flags & PLH::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & PLH::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & PLH::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::UNSET;

	if(prot & PROT_EXEC)
		flags = flags | PLH::ProtFlag::X;

	if (prot & PROT_READ)
		flags = flags | PLH::ProtFlag::R;

	if (prot & PROT_WRITE)
		flags = flags | PLH::ProtFlag::W;

	if (prot == PROT_NONE)
		flags = flags | PLH::ProtFlag::NONE;

	return flags;
}

#elif defined(POLYHOOK2_OS_APPLE)

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = VM_PROT_NONE;
	if (flags & PLH::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & PLH::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & PLH::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::UNSET;

	if (prot & VM_PROT_EXECUTE)
		flags = flags | PLH::ProtFlag::X;

	if (prot & VM_PROT_READ)
		flags = flags | PLH::ProtFlag::R;

	if (prot & VM_PROT_WRITE)
		flags = flags | PLH::ProtFlag::W;

	if (prot == VM_PROT_NONE)
		flags = flags | PLH::ProtFlag::NONE;

	return flags;
}

#endif