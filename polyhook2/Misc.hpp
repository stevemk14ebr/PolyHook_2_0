//
// Created by steve on 4/6/17.
//

#pragma once

#include "polyhook2/PolyHookOs.hpp"

namespace PLH {

/**First param is an address to a function that you want to
cast to the type of pFnCastTo. Second param must be a pointer
to function type**/
template<typename FnCastTo>
FnCastTo FnCast(uint64_t fnToCast, FnCastTo) {
    return (FnCastTo) fnToCast;
}

template<typename FnCastTo>
FnCastTo FnCast(void* fnToCast, FnCastTo) {
    return (FnCastTo) fnToCast;
}

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
static inline uint64_t AlignUpwards(uint64_t stack, size_t align) {
	assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
	assert(stack != 0);

	auto addr = stack;
	if (addr % align != 0)
		addr += align - (addr % align);
	assert(addr >= stack);
	return addr;
}

static inline uint64_t AlignDownwards(uint64_t stack, size_t align) {
	assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
	assert(stack != 0);

	auto addr = stack;
	addr -= addr % align;
	assert(addr <= stack);
	return addr;
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
#ifdef POLYHOOK2_ARCH_X64
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

struct ci_wchar_traits : public std::char_traits<wchar_t> {
    static bool eq(wchar_t c1, wchar_t c2) { return towupper(c1) == towupper(c2); }
    static bool ne(wchar_t c1, wchar_t c2) { return towupper(c1) != towupper(c2); }
    static bool lt(wchar_t c1, wchar_t c2) { return towupper(c1) < towupper(c2); }
    static int compare(const wchar_t* s1, const wchar_t* s2, size_t n) {
        while (n-- != 0) {
            if (towupper(*s1) < towupper(*s2)) return -1;
            if (towupper(*s1) > towupper(*s2)) return 1;
            ++s1; ++s2;
        }
        return 0;
    }
    static const wchar_t* find(const wchar_t* s, int n, wchar_t a) {
        while (n-- > 0 && towupper(*s) != towupper(a)) {
            ++s;
        }
        return s;
    }
};

inline bool isMatch(const char* addr, const char* pat, const char* msk)
{
	size_t n = 0;
	while (addr[n] == pat[n] || msk[n] == (uint8_t)'?') {
		if (!msk[++n]) {
			return true;
		}
	}
	return false;
}

#define INRANGE(x,a,b)		(x >= a && x <= b)
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

constexpr uint8_t FINDPATTERN_SCRATCH_SIZE = 64;

// https://github.com/learn-more/findpattern-bench/blob/master/patterns/learn_more.h
// must use space between bytes and ?? for wildcards. Do not add 0x prefix
uint64_t findPattern(const uint64_t rangeStart, size_t len, const char* pattern);
uint64_t findPattern_rev(const uint64_t rangeStart, size_t len, const char* pattern);
uint64_t getPatternSize(const char* pattern);

bool boundedAllocSupported();
uint64_t boundAlloc(uint64_t min, uint64_t max, uint64_t size);
uint64_t boundAllocLegacy(uint64_t min, uint64_t max, uint64_t size);
void     boundAllocFree(uint64_t address, uint64_t size);
size_t getAllocationAlignment();
size_t getPageSize();

uint64_t calc_2gb_below(uint64_t address);
uint64_t calc_2gb_above(uint64_t address);

inline std::string repeat_n(std::string s, size_t n, std::string delim = "") {
	std::string out = "";
	for (size_t i = 0; i < n; i++) {
		out += s;
		if (i != n - 1) {
			out += delim;
		}
	}
	return out;
}

using ci_wstring = std::basic_string<wchar_t, ci_wchar_traits>;
using ci_wstring_view = std::basic_string_view<wchar_t, ci_wchar_traits>;

template< typename T >
std::string int_to_hex(T i)
{
	std::stringstream stream;
	stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex
		<< (uint64_t) i; // We cast to the highest possible int because uint8_t will be printed as char

	return stream.str();
}

template< typename T >
inline bool vector_contains(std::vector<T> vec, T element)
{
	return std::find(vec.begin(), vec.end(), element) != vec.end();
}

inline bool string_contains(const std::string& str, const std::string& sub_str)
{
	return str.find(sub_str) != std::string::npos;
}

}
