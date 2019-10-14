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
option(BUILD_DLL "Build dll & lib instead of tests" OFF)
option(BUILD_STATIC "If BUILD_DLL is set, create the type that can be statically linked" ON)
option(CAPSTONE_FULL "Build all features of capstone." OFF)

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
		${PROJECT_SOURCE_DIR}/sources/TestEffectTracker.cpp
		${PROJECT_SOURCE_DIR}/sources/PageAllocator.cpp)

# only build tests if making exe
if(BUILD_DLL MATCHES OFF)	
	set(UNIT_TEST_SOURCES 
			${PROJECT_SOURCE_DIR}/MainTests.cpp
			${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
			${PROJECT_SOURCE_DIR}/UnitTests/TestMemProtector.cpp)
else()
	set(UNIT_TEST_SOURCES)
endif()

# Headers, Sources, and Test for detours
if(FEATURE_DETOURS MATCHES ON) 
	set(DETOUR_HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/Detour/ADetour.hpp
			${PROJECT_SOURCE_DIR}/headers/Detour/x64Detour.hpp
			${PROJECT_SOURCE_DIR}/headers/Detour/x86Detour.hpp)

	set(DETOUR_IMP_SOURCES 
			${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
			${PROJECT_SOURCE_DIR}/sources/x64Detour.cpp
			${PROJECT_SOURCE_DIR}/sources/x86Detour.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${DETOUR_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${DETOUR_IMP_SOURCES})

	# only build tests if making exe
	if(BUILD_DLL MATCHES OFF)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			# 64 bits
			set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
				${PROJECT_SOURCE_DIR}/UnitTests/TestDetourx64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
			# 32 bits
			set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
				${PROJECT_SOURCE_DIR}/UnitTests/TestDetourx86.cpp)
		endif()
	endif()
endif()

if(FEATURE_EXCEPTION MATCHES ON)
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

	# only build tests if making exe
	if(BUILD_DLL MATCHES OFF)
		set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
				${PROJECT_SOURCE_DIR}/UnitTests/TestBreakpointHook.cpp
				${PROJECT_SOURCE_DIR}/UnitTests/TestHWBreakpointHook.cpp)
	endif()
endif()

if(FEATURE_VIRTUALS MATCHES ON)
	set(VIRTUAL_HEADER_FILES 
		${PROJECT_SOURCE_DIR}/headers/Virtuals/VTableSwapHook.hpp
		${PROJECT_SOURCE_DIR}/headers/Virtuals/VFuncSwapHook.hpp)

	set(VIRTUAL_IMP_SOURCES
		${PROJECT_SOURCE_DIR}/sources/VTableSwapHook.cpp
		${PROJECT_SOURCE_DIR}/sources/VFuncSwapHook.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${VIRTUAL_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${VIRTUAL_IMP_SOURCES})

	# only build tests if making exe
	if(BUILD_DLL MATCHES OFF)
		set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES} 
				${PROJECT_SOURCE_DIR}/UnitTests/TestVTableSwapHook.cpp
				${PROJECT_SOURCE_DIR}/UnitTests/TestVFuncSwapHook.cpp)
	endif()
endif()

if(FEATURE_PE MATCHES ON)
	set(PE_HEADER_FILES
		${PROJECT_SOURCE_DIR}/headers/PE/EatHook.hpp
		${PROJECT_SOURCE_DIR}/headers/PE/IatHook.hpp
		${PROJECT_SOURCE_DIR}/headers/PE/PEB.hpp)

	set(PE_IMP_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/EatHook.cpp
		${PROJECT_SOURCE_DIR}/sources/IatHook.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${PE_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${PE_IMP_SOURCES})

	# only build tests if making exe
	if(BUILD_DLL MATCHES OFF)
		set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES}
				${PROJECT_SOURCE_DIR}/UnitTests/TestEatHook.cpp
				${PROJECT_SOURCE_DIR}/UnitTests/TestIatHook.cpp)
	endif()
endif()

if(FEATURE_INLINENTD MATCHES ON)
	set(NTD_HEADER_FILES
		${PROJECT_SOURCE_DIR}/headers/Detour/ILCallback.hpp)

	set(NTD_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/ILCallback.cpp)

	set(HEADER_FILES ${HEADER_FILES} ${NTD_HEADER_FILES})
	set(HEADER_IMP_SOURCES ${HEADER_IMP_SOURCES} ${NTD_SOURCES})

	# only build tests if making exe
	if(BUILD_DLL MATCHES OFF)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			# 64 bits
			set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES}
				${PROJECT_SOURCE_DIR}/UnitTests/TestDetourNoTDx64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
			# 32 bits
			set(UNIT_TEST_SOURCES ${UNIT_TEST_SOURCES}
				${PROJECT_SOURCE_DIR}/UnitTests/TestDetourNoTDx86.cpp)
		endif()
	endif()
endif()

include_directories(${PROJECT_SOURCE_DIR})
set(SOURCE_FILES_PLH ${UNIT_TEST_SOURCES} ${HEADER_IMP_SOURCES} ${HEADER_FILES})

if(BUILD_DLL MATCHES ON) 
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
	if(BUILD_STATIC MATCHES ON)
	    add_library(PolyHook_2 STATIC ${SOURCE_FILES_PLH})
	else()
	    add_library(PolyHook_2 SHARED ${SOURCE_FILES_PLH})
	endif()
else()
    add_executable(PolyHook_2 ${SOURCE_FILES_PLH})
endif()

# add WALL + PDB flags
if(MSVC)
  # apply wall flags only to plh src files
  set_property(SOURCE ${SOURCE_FILES_PLH} PROPERTY COMPILE_FLAGS "/MP /W4 /WX /Z7")
  target_link_libraries(PolyHook_2 optimized -DEBUG) # mhhm ya pdbs

  # force static lib
  set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
	foreach(CompilerFlag ${CompilerFlags})
		string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
	endforeach()
endif()

# build and link all the deps

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
target_link_libraries(${PROJECT_NAME} capstone-static)

# ASMJIT
if(DEP_ASMJIT_NEED MATCHES ON)
	# AsmJit is a dep iff inlinetd is on
	set(ASMJIT_DIR ${PROJECT_SOURCE_DIR}/asmjit/)
	set(ASMJIT_BUILD_STATIC ON) # give our project the BUILD_STATIC flag
	add_definitions(-DASMJIT_BUILD_STATIC) # give asmjit the BUILD_STATIC flag
	include_directories(${ASMJIT_DIR}/src/) # includes directory is nested in src
	add_subdirectory(${ASMJIT_DIR}) # build it
	target_link_libraries(${PROJECT_NAME} asmjit)
endif()
