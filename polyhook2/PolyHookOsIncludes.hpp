#ifndef POLYHOOK_2_OS_INCLUDES_HPP
#define POLYHOOK_2_OS_INCLUDES_HPP

#if defined(POLYHOOK2_OS_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <windows.h>

#elif defined(POLYHOOK2_OS_LINUX)

#include <sys/mman.h>
#include <unistd.h>

#elif defined(POLYHOOK2_OS_APPLE)

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>

#endif

#endif