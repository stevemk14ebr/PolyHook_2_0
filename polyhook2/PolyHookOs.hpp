#ifndef POLYHOOK_2_OS_HPP
#define POLYHOOK_2_OS_HPP

#if defined(WIN64) || defined(_WIN64) || defined(__MINGW64__)
    #define POLYHOOK2_OS_WINDOWS
    #define POLYHOOK2_ARCH_X64
#elif defined(WIN32) || defined(_WIN32) || defined(__MINGW32__)
    #define POLYHOOK2_OS_WINDOWS
    #define POLYHOOK2_ARCH_X86
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
void* PolyHook2Alloca(size_t size);

#endif
