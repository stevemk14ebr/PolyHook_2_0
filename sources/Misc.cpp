#include "polyhook2/Misc.hpp"

uint64_t PLH::findPattern(const uint64_t rangeStart, size_t len, const char* pattern)
{
	const size_t l = strlen(pattern);

	// l = 2 * b + (b - 1) . 2 chars per byte + b - 1 spaces between
	const size_t patSize = (l + 1) / 3;
	auto patt_base = (char*)_alloca(patSize + 1);
	auto msk_base = (char*)_alloca(patSize + 1);
	char* pat = patt_base;
	char* msk = msk_base;

	if (patSize + 1 > len)
		return NULL;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = 0; n < (len - (patSize + 1)); ++n)
	{
		if (isMatch((char*)(rangeStart + n), patt_base, msk_base)) {
			return rangeStart + n;
		}
	}
	return NULL;
}

uint64_t PLH::findPattern_rev(const uint64_t rangeStart, size_t len, const char* pattern)
{
	const size_t l = strlen(pattern);

	// c = 2 * b + (b - 1) . 2 chars per byte + b - 1 spaces between
	const size_t patSize = (l + 1) / 3;
	auto patt_base = (char*)_alloca(patSize + 1);
	auto msk_base = (char*)_alloca(patSize + 1);
	char* pat = patt_base;
	char* msk = msk_base;

	if (patSize + 1 > len)
		return NULL;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = len - (patSize + 1); n > 0; n--)
	{
		if (isMatch((char*)(rangeStart + n), patt_base, msk_base)) {
			return rangeStart + n;
		}
	}
	return NULL;
}