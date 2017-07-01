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

set(PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR})

set(SOURCE_FILES_PLH ${PROJECT_SOURCE_DIR}/MainTests.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestErrorSystem.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/UnixTests/TestMemAllocator.cpp
        )
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


