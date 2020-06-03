#include "polyhook2/UID.hpp"

PLH::UID::UID(long val) {
	this->val = val;
}

std::atomic_long& PLH::UID::singleton() {
	static std::atomic_long base = { -1 };
	base++;
	return base;
}
