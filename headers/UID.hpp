//
// Created by steve on 6/23/17.
//

#ifndef POLYHOOK_2_UID_HPP
#define POLYHOOK_2_UID_HPP

#include <atomic>

class UID {
public:
	UID(long val) {
		this->val = val;
	}

	static std::atomic_long& singleton() {
		static std::atomic_long base = {-1};
		base++;
		return base;
	}

	long	val;
};
#endif //POLYHOOK_2_UID_HPP