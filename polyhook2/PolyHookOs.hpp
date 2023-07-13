#ifndef POLYHOOK_2_OS_HPP
#define POLYHOOK_2_OS_HPP

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__)
#define POLYHOOK2_OS_WINDOWS
#define POLYHOOK2_ARCH_X64

#ifdef __GNUC__

// VirtualAlloc2 requires NTDII_WIN10_RS4 on my distrubition of mingw
#define NTDDI_VERSION NTDDI_WIN10_RS4 

// This was taken from Microsofts Detours library 
#define ERROR_DYNAMIC_CODE_BLOCKED 1655L

#endif

#elif defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
#define POLYHOOK2_OS_WINDOWS
#define POLYHOOK2_ARCH_X86

#ifdef __GNUC__

// VirtualAlloc2 requires NTDII_WIN10_RS4 on my distrubition of mingw
#define NTDDI_VERSION NTDDI_WIN10_RS4 

// This was taken from Microsofts Detours library 
#define ERROR_DYNAMIC_CODE_BLOCKED 1655L

#endif

#elif defined(__linux__) || defined(linux)
#if defined(__x86_64__)
#define POLYHOOK2_OS_LINUX
#define POLYHOOK2_ARCH_X64
#else
#define POLYHOOK2_OS_LINUX
#define POLYHOOK2_ARCH_X86
#endif
#elif defined(__APPLE__)
#if defined(__x86_64__)
#define POLYHOOK2_OS_APPLE
#define POLYHOOK2_ARCH_X64
#else
#define POLYHOOK2_OS_APPLE
#define POLYHOOK2_ARCH_X86
#endif
#endif

#if defined(_MSC_VER)
#define PLH_INLINE __forceinline
#elif defined(__GNUC__)
#define PLH_INLINE inline __attribute__((always_inline))
#else
#define PLH_INLINE inline
#endif

#include <iostream> //for debug printing
#include <sstream>
#include <iomanip> //setw
#include <fstream>

#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <filesystem>

#include <mutex>
#include <atomic>

#include <memory>
#include <stdexcept>
#include <limits>
#include <functional>
#include <optional>
#include <algorithm>
#include <type_traits>
#include <tuple>
#include <utility>

#include <cctype>
#include <cassert>
#include <cstring>

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

void PolyHook2DebugBreak();
#endif
