#include "polyhook2/Tests/StackCanary.hpp"

PLH::StackCanary::StackCanary() {
	for (int i = 0; i < 50; i++) {
		buf[i] = 0xCE;
	}
}

bool PLH::StackCanary::isStackGood() {
	for (int i = 0; i < 50; i++) {
		if (buf[i] != 0xCE)
			return false;
	}
	return true;
}

PLH::StackCanary::~StackCanary() noexcept(false) {
	if (!isStackGood())
		throw "Stack corruption detected";
}