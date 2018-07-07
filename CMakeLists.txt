cmake_minimum_required(VERSION 3.6)
project(PolyHook_2)

#set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
#set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
#set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

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
		${PROJECT_SOURCE_DIR}/headers/MemAllocator.hpp)

set(DETOUR_HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/Detour/ADetour.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x64Detour.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x86Detour.hpp)

#TODO: Setup source groups using the header file variables above

include_directories(${PROJECT_SOURCE_DIR})

set(UNIT_TEST_SOURCES 
		${PROJECT_SOURCE_DIR}/MainTests.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestMemProtector.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/TestDetour.cpp)

set(HEADER_IMP_SOURCES 
		${PROJECT_SOURCE_DIR}/sources/CapstoneDisassembler.cpp
		${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
		${PROJECT_SOURCE_DIR}/sources/MemProtector.cpp
        ${PROJECT_SOURCE_DIR}/sources/x64Detour.cpp
        ${PROJECT_SOURCE_DIR}/sources/x86Detour.cpp)

set(SOURCE_FILES_PLH ${UNIT_TEST_SOURCES} ${HEADER_IMP_SOURCES} ${HEADER_FILES} ${DETOUR_HEADER_FILES})

add_executable(PolyHook_2 ${SOURCE_FILES_PLH})
target_compile_options(PolyHook_2 PRIVATE /std:c++latest)
if(MSVC)
  target_compile_options(PolyHook_2 PRIVATE /W4 /WX)
else(MSVC)
  target_compile_options(PolyHook_2 PRIVATE -Wall -Wextra -pedantic -Werror)
endif(MSVC)

#Set this variable to hold the path to capstone directory
set(CAPSTONE_LIB_PATH_64 ${PROJECT_SOURCE_DIR}/capstone/build32)
set(CAPSTONE_LIB_PATH_86 ${PROJECT_SOURCE_DIR}/capstone/build64)

#Find the absolute path to the lib (linux)
#find_library(CAPSTONE_LIB NAMES libcapstone.a PATHS ${CAPSTONE_LIB_PATH})

#Link the capstone lib according to config mode
target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_86}/Debug/capstone.lib)
target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_86}/Release/capstone.lib)

