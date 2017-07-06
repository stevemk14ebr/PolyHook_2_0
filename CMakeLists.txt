cmake_minimum_required(VERSION 3.6)
project(PolyHook_2)

set(BUILD32 true)

if(BUILD32)
    set(CMAKE_C_FLAGS -m32)
    set(CMAKE_CXX_FLAGS -m32)
endif()

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

#IDE's like it when header file are included as source files
set(HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/ADisassembler.hpp
        ${PROJECT_SOURCE_DIR}/headers/CapstoneDisassembler.hpp
        ${PROJECT_SOURCE_DIR}/headers/Enums.hpp
        ${PROJECT_SOURCE_DIR}/headers/ErrorSystem.hpp
        ${PROJECT_SOURCE_DIR}/headers/IHook.hpp
        ${PROJECT_SOURCE_DIR}/headers/Instruction.hpp
        ${PROJECT_SOURCE_DIR}/headers/Maybe.hpp
        ${PROJECT_SOURCE_DIR}/headers/Misc.hpp
        ${PROJECT_SOURCE_DIR}/headers/UID.hpp)

set(DETOUR_HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/Detour/ADetour.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x64DetourImp.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x86DetourImp.hpp)

set(MEM_ALLOC_HEADER_FILES  ${PROJECT_SOURCE_DIR}/headers/MemoryAllocation/AllocatedMemoryBlock.hpp
        ${PROJECT_SOURCE_DIR}/headers/MemoryAllocation/ARangAllocator.hpp
        ${PROJECT_SOURCE_DIR}/headers/MemoryAllocation/MemoryBlock.hpp
        ${PROJECT_SOURCE_DIR}/headers/MemoryAllocation/RangeAllocator.hpp
        ${PROJECT_SOURCE_DIR}/headers/MemoryAllocation/UnixImpl/RangeMemAllocatorUnixImp.hpp)

#TODO: Setup source groups using the header file variables above

include_directories(${PROJECT_SOURCE_DIR})

set(UNIT_TEST_SOURCES ${PROJECT_SOURCE_DIR}/MainTests.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestErrorSystem.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/UnixTests/TestMemAllocator.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDetour.cpp)

set(HEADER_IMP_SOURCES ${PROJECT_SOURCE_DIR}/sources/CapstoneDisassembler.cpp
        ${PROJECT_SOURCE_DIR}/sources/AllocatedMemoryBlock.cpp
        ${PROJECT_SOURCE_DIR}/sources/MemoryBlock.cpp
        ${PROJECT_SOURCE_DIR}/sources/RangeMemAllocatorUnixImp.cpp
        ${PROJECT_SOURCE_DIR}/sources/x64DetourImp.cpp
        ${PROJECT_SOURCE_DIR}/sources/x86DetourImp.cpp)

set(SOURCE_FILES_PLH ${UNIT_TEST_SOURCES} ${HEADER_IMP_SOURCES} ${HEADER_FILES} ${DETOUR_HEADER_FILES} ${MEM_ALLOC_HEADER_FILES})

add_executable(PolyHook_2 ${SOURCE_FILES_PLH})

find_package(Boost)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

#To build capstone for 32bit use:
#cmake -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 ../
#Set this variable to hold the path to capstone directory
set(CAPSTONE_LIB_PATH ${PROJECT_SOURCE_DIR}/capstone/build/)

#Find the absolute path to the lib
find_library(CAPSTONE_LIB NAMES libcapstone.a PATHS ${CAPSTONE_LIB_PATH})

#Link the capstone lib
target_link_libraries(${PROJECT_NAME} ${CAPSTONE_LIB})


