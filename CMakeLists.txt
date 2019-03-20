cmake_minimum_required(VERSION 3.6)
project(PolyHook_2)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Turn Features On/Off, Set build options
option(FEATURE_DETOURS "Implement detour functionality" ON)
option(FEATURE_EXCEPTION "Implement all exception hooking functionality" ON)
option(FEATURE_VIRTUALS "Implement all virtual table hooking functionality" ON)
option(FEATURE_INLINENTD "Support inline hooks without specifying typedefs by generating callback stubs at runtime with AsmJit" ON)
option(FEATURE_PE "Implement all win pe hooking functionality" ON)
option(CAPSTONE_FULL "Build all features of capstone." OFF)

# CAPSTONE
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "")
if(NOT ${CAPSTONE_FULL})
	set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "ARM support") 
	set(CAPSTONE_ARM64_SUPPORT OFF CACHE BOOL "ARM64 support") 
	set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "M680X support") 
	set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "M68K support") 
	set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "MIPS support") 
	set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "PPC support") 
	set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "SPARC support")
	set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "SYSZ support")
	set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "XCORE support")
	set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "TMS320C64X support")
	set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "M680X support")
	set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "EVM support")
endif()

add_subdirectory(capstone) 

# Detect architecture, it determines if x86 or x64 hooks will be build 
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	message("Detected 64 bit")
	set(ARCHITECTURE x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
	message("Detected 32 bit")
	set(ARCHITECTURE x86)
endif()

# Calculate inclusion of necessary dependencies based on features

# for now only inlinentd uses asmjit
set(DEP_ASMJIT_NEED ${FEATURE_INLINENTD})
# todo: make inclusion of capstone stuff depend on feature flags

#IDE's like it when header file are included as source files
set(HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/ADisassembler.hpp
		${PROJECT_SOURCE_DIR}/headers/CapstoneDisassembler.hpp
		${PROJECT_SOURCE_DIR}/headers/Enums.hpp
		${PROJECT_SOURCE_DIR}/headers/IHook.hpp
		${PROJECT_SOURCE_DIR}/headers/Instruction.hpp
		${PROJECT_SOURCE_DIR}/headers/Misc.hpp
		${PROJECT_SOURCE_DIR}/headers/UID.hpp
		${PROJECT_SOURCE_DIR}/headers/ErrorLog.hpp
		${PROJECT_SOURCE_DIR}/headers/MemProtector.hpp 
		${PROJECT_SOURCE_DIR}/headers/PageAllocator.hpp) 

set(HEADER_IMP_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/CapstoneDisassembler.cpp
		${PROJECT_SOURCE_DIR}/sources/MemProtector.cpp
		${PROJECT_SOURCE_DIR}/sources/TestEffectTracker.cpp)

set(UNIT_TEST_SOURCES 
		${PROJECT_SOURCE_DIR}/MainTests.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestMemProtector.cpp)

# Headers, Sources, and Test for detours
if(FEATURE_DETOURS MATCHES ON) 
	message("Building Implement detour functionality")
	set(DETOUR_HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/Detour/ADetour.hpp
			${PROJECT_SOURCE_DIR}/headers/Detour/${ARCHITECTURE}Detour.hpp)

	set(DETOUR_IMP_SOURCES 
			${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
			${PROJECT_SOURCE_DIR}/sources/${ARCHITECTURE}Detour.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${DETOUR_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${DETOUR_IMP_SOURCES})

	set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
		${PROJECT_SOURCE_DIR}/UnitTests/TestDetour${ARCHITECTURE}.cpp)
endif()

if(FEATURE_EXCEPTION MATCHES ON)
	message("Building exception hooking functionality")
	set(EXCEPTION_HEADER_FILES 
		${PROJECT_SOURCE_DIR}/headers/Exceptions/AVehHook.hpp
		${PROJECT_SOURCE_DIR}/headers/Exceptions/BreakPointHook.hpp
		${PROJECT_SOURCE_DIR}/headers/Exceptions/HWBreakPointHook.hpp)

	set(EXCEPTION_IMP_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/AVehHook.cpp
		${PROJECT_SOURCE_DIR}/sources/BreakPointHook.cpp
		${PROJECT_SOURCE_DIR}/sources/HWBreakPointHook.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${EXCEPTION_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${EXCEPTION_IMP_SOURCES})

	set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
		${PROJECT_SOURCE_DIR}/UnitTests/TestBreakpointHook.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestHWBreakpointHook.cpp)
endif()

if(FEATURE_VIRTUALS MATCHES ON)
	message("Building virtual table hooking functionality")
	set(VIRTUAL_HEADER_FILES 
		${PROJECT_SOURCE_DIR}/headers/Virtuals/VTableSwapHook.hpp
		${PROJECT_SOURCE_DIR}/headers/Virtuals/VFuncSwapHook.hpp)

	set(VIRTUAL_IMP_SOURCES
		${PROJECT_SOURCE_DIR}/sources/VTableSwapHook.cpp
		${PROJECT_SOURCE_DIR}/sources/VFuncSwapHook.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${VIRTUAL_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${VIRTUAL_IMP_SOURCES})

	set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
		${PROJECT_SOURCE_DIR}/UnitTests/TestVTableSwapHook.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestVFuncSwapHook.cpp)
endif()

if(FEATURE_PE MATCHES ON)
	message("building win pe hooking functionality")
	set(PE_HEADER_FILES
		${PROJECT_SOURCE_DIR}/headers/PE/EatHook.hpp
		${PROJECT_SOURCE_DIR}/headers/PE/IatHook.hpp
		${PROJECT_SOURCE_DIR}/headers/PE/PEB.hpp)

	set(PE_IMP_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/EatHook.cpp
		${PROJECT_SOURCE_DIR}/sources/IatHook.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${PE_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${PE_IMP_SOURCES})

	set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES}
			${PROJECT_SOURCE_DIR}/UnitTests/TestEatHook.cpp
			${PROJECT_SOURCE_DIR}/UnitTests/TestIatHook.cpp)
endif()

include_directories(${PROJECT_SOURCE_DIR})
if(FEATURE_INLINENTD MATCHES ON)
	message("building inline hooks")
	set(NTD_HEADER_FILES
		${PROJECT_SOURCE_DIR}/headers/Detour/ILCallback.hpp
		${PROJECT_SOURCE_DIR}/headers/PageAllocator.hpp
		)
	
	set(NTD_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/ILCallback.cpp
		${PROJECT_SOURCE_DIR}/sources/PageAllocator.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${NTD_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${NTD_SOURCES})
	
	set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
		${PROJECT_SOURCE_DIR}/UnitTests/TestDetourNoTD${ARCHITECTURE}.cpp)
endif()

set(SOURCE_FILES_PLH ${HEADER_IMP_SOURCES} ${HEADER_FILES})

add_library(PolyHook_2 ${SOURCE_FILES_PLH})
add_executable(TestRunner ${SOURCE_FILES_PLH} ${UNIT_TEST_SOURCES})

# require c++ 17 (for std::optional) and add WALL + PDB flags
if(MSVC)
	set(MY_DEBUG_OPTIONS /MP /W4 /WX /Z7)
endif()

# build and link all the deps


target_compile_options(PolyHook_2 PUBLIC "$<$<CONFIG:DEBUG>:${MY_DEBUG_OPTIONS}>")
target_compile_options(PolyHook_2 PUBLIC "$<$<CONFIG:RELEASE>:${MY_DEBUG_OPTIONS}>")

target_compile_options(TestRunner PUBLIC "$<$<CONFIG:DEBUG>:${MY_DEBUG_OPTIONS}>")
target_compile_options(TestRunner PUBLIC "$<$<CONFIG:RELEASE>:${MY_DEBUG_OPTIONS}>")

target_link_libraries(PolyHook_2 PUBLIC capstone-static)

target_link_libraries(TestRunner PUBLIC capstone-static)

# ASMJIT
if(DEP_ASMJIT_NEED MATCHES ON)
	# AsmJit is a dep iff inlinetd is on
	set(ASMJIT_DIR ${PROJECT_SOURCE_DIR}/asmjit/)
	set(ASMJIT_BUILD_STATIC ON) # give our project the BUILD_STATIC flag
	add_definitions(-DASMJIT_BUILD_STATIC) # give asmjit the BUILD_STATIC flag
	include_directories(${ASMJIT_DIR}/src/) # includes directory is nested in src
	add_subdirectory(${ASMJIT_DIR}) # build it
	target_link_libraries(PolyHook_2 PUBLIC asmjit)
	target_link_libraries(TestRunner PUBLIC asmjit)
endif()
