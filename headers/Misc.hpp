//
// Created by steve on 4/6/17.
//

#ifndef POLYHOOK_2_0_MISC_HPP
#define POLYHOOK_2_0_MISC_HPP

#include <stdexcept>
#include <cassert>

namespace PLH {

enum class Platform {
	WIN,
	UNIX
};

class NotImplementedException : public std::logic_error {
public:
	NotImplementedException() : std::logic_error("Function not implemented") {

	}
};

class ValueNotSetException : public std::logic_error {
public:
	ValueNotSetException() : std::logic_error("Value not set in optional object") {

	}
};

class AllocationFailure : public std::logic_error {
public:
	AllocationFailure() : std::logic_error("Unable to allocate memory within range") {

	}
};

//http://stackoverflow.com/questions/4840410/how-to-align-a-pointer-in-c
static inline char* AlignUpwards(const char* stack, size_t align) {
	assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
	assert(stack != 0);

	auto addr = reinterpret_cast<uintptr_t>(stack);
	if (addr % align != 0)
		addr += align - addr % align;
	assert(addr >= reinterpret_cast<uintptr_t>(stack));
	return reinterpret_cast<char*>(addr);
}

static inline char* AlignDownwards(const char* stack, size_t align) {
	assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
	assert(stack != 0);

	auto addr = reinterpret_cast<uintptr_t>(stack);
	addr -= addr % align;
	assert(addr <= reinterpret_cast<uintptr_t>(stack));
	return reinterpret_cast<char*>(addr);
}

template<typename Func>
class FinalAction {
public:
	FinalAction(Func f) :FinalActionFunc(std::move(f)) {}
	~FinalAction() {
		FinalActionFunc();
	}
private:
	Func FinalActionFunc;

	/*Uses RAII to call a final function on destruction
	C++ 11 version of java's finally (kindof)*/
};

template <typename F>
static inline FinalAction<F> finally(F f) {
	return FinalAction<F>(f);
}

//Credit to Dogmatt on unknowncheats.me for IsValidPtr
// and https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
#ifdef _WIN64
#define _PTR_MAX_VALUE ((void*)0x000F000000000000)
#else
#define _PTR_MAX_VALUE ((void*)0xFFF00000)
#endif

inline bool IsValidPtr(void* p) { return (p >= (void*)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr; }

// wtf this should be standard (stole from glibc & stackoverflow)
inline int my_narrow_stricmp(const char *a, const char *b) {
	int ca, cb;
	do {
		ca = (unsigned char)*a++;
		cb = (unsigned char)*b++;
		ca = tolower(toupper(ca));
		cb = tolower(toupper(cb));
	} while (ca == cb && ca != '\0');
	return ca - cb;
}

inline int my_wide_stricmp(const wchar_t *a, const wchar_t *b) {
	wint_t ca, cb;
	do {
		ca = (wint_t)*a++;
		cb = (wint_t)*b++;
		ca = towlower(towupper(ca));
		cb = towlower(towupper(cb));
	} while (ca == cb && ca != L'\0');
	return ca - cb;
}

}
#endif //POLYHOOK_2_0_MISC_HPP
