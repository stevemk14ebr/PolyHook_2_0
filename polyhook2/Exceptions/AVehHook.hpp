#ifndef POLYHOOK_2_0_VEHHOOK_HPP
#define POLYHOOK_2_0_VEHHOOK_HPP

#include <cassert>
#include <unordered_set>

#include "polyhook2/MemProtector.hpp"
#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/IHook.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/EventDispatcher.hpp"

namespace PLH {

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif // _WIN64

class RefCounter {
public:
	uint16_t m_count = 0;
};

enum class AVehHookImpType {
	SINGLE, // will exception occur at one address (end address ignored)
	RANGE // will exception occur over a potential range
};

class AVehHook;
struct AVehHookImpEntry {
	uint64_t startAddress; // start address impl applies to
	uint64_t endAddress; // end address impl applies to
	AVehHook* impl; // the instance to forward to
	AVehHookImpType type;

	AVehHookImpEntry(uint64_t start, AVehHook* imp) {
		startAddress = start;
		endAddress = 0;
		impl = imp;
		type = AVehHookImpType::SINGLE;
	}

	AVehHookImpEntry(uint64_t start, uint64_t end, AVehHook* imp) {
		startAddress = start;
		endAddress = end;
		impl = imp;
		type = AVehHookImpType::RANGE;
	}
};

inline bool operator==(const AVehHookImpEntry& lhs, const AVehHookImpEntry& rhs)
{
	return lhs.type == rhs.type && lhs.startAddress == rhs.startAddress && lhs.endAddress == rhs.endAddress;
}




typedef EventDispatcher<bool(EXCEPTION_POINTERS* exceptionInfo, DWORD* returnCode)> eException;
class AVehHook : public IHook {
public:
	AVehHook();
	virtual ~AVehHook();

	virtual HookType getType() const {
		return HookType::VEHHOOK;
	}

	/**If true is returned**/
	static eException& EventException();
	static eException& EventUnhandledException();
protected:
	// May not allocate or acquire synchonization objects in this
	virtual LONG OnException(EXCEPTION_POINTERS* ExceptionInfo) = 0;

	static RefCounter m_refCount;
	static void* m_hHandler;
	static std::unordered_set<AVehHookImpEntry> m_impls;
	static LONG CALLBACK Handler(EXCEPTION_POINTERS* ExceptionInfo);
	static eException m_onException;
	static eException m_onUnhandledException;
};
}

namespace std {
	template<> struct hash<PLH::AVehHookImpEntry>
	{
		std::size_t operator()(const PLH::AVehHookImpEntry& e) const noexcept
		{
			auto h1 = std::hash<uint64_t>{}(e.startAddress);
			auto h2 = std::hash<uint64_t>{}(e.endAddress);
			return h1 ^ (h2 << 1);
		}
	};
}

#endif