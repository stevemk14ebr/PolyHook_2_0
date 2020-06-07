#pragma once

namespace PLH {
	class StackCanary {
	public:
		StackCanary();
		bool isStackGood();
		~StackCanary() noexcept(false);
	private:
		unsigned char buf[50];
	};
}