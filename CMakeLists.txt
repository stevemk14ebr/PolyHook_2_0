cmake_minimum_required(VERSION 3.6)
project(PolyHook_2)

option(FEATURE_DETOURS "Implement detour functionality" ON)
option(FEATURE_EXCEPTION "Implement all exception hooking functionality" ON)
option(FEATURE_VIRTUALS "Implement all virtual table hooking functionality" ON)
option(FEATURE_PE "Implement all win pe hooking functionality" ON)
option(BUILD_DLL "Build dll & lib instead of tests" OFF)
option(BUILD_STATIC "If BUILD_DLL is set, create the type that can be statically linked" ON)

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

set(UNIT_TEST_SOURCES 
		${PROJECT_SOURCE_DIR}/MainTests.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestMemProtector.cpp)

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

# require c++ 17 (for std::optional) and add WALL + PDB flags
target_compile_options(PolyHook_2 PRIVATE /std:c++latest)
if(MSVC)
  target_compile_options(PolyHook_2 PRIVATE /W4 /WX /Z7)
  target_link_libraries(PolyHook_2 optimized -DEBUG) # mhhm ya pdbs
endif()

#Set this variable to hold the path to capstone directory
set(CAPSTONE_LIB_PATH_64 ${PROJECT_SOURCE_DIR}/capstone/build64)
set(CAPSTONE_LIB_PATH_86 ${PROJECT_SOURCE_DIR}/capstone/build32)

#Find the absolute path to the lib (linux)
#find_library(CAPSTONE_LIB NAMES libcapstone.a PATHS ${CAPSTONE_LIB_PATH})

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
	
	#Link the capstone lib according to config mode
	target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_64}/Debug/capstone.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_64}/Release/capstone.lib)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits

	#Link the capstone lib according to config mode
	target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_86}/Debug/capstone.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_86}/Release/capstone.lib)
endif()