//
// Created by steve on 6/23/17.
//

#ifndef POLYHOOK_2_UID_HPP
#define POLYHOOK_2_UID_HPP

#include <atomic>
namespace PLH {
	class UID {
	public:
		UID(long val);
		static std::atomic_long& singleton();

		long val;
	};
}
#endif //POLYHOOK_2_UID_HPP