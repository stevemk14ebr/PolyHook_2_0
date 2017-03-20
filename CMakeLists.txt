cmake_minimum_required(VERSION 3.6)
project(PolyHook_2_0)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES MainTests.cpp PolyHook.h Catch.hpp UnitTests/ErrorSystem.cpp)

set(CAPSTONE_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/capstone)
find_library(CAPSTONE_LIB NAMES libcapstone PATHS ${CAPSTONE_LIB_PATH})
add_executable(PolyHook_2_0 ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} ${CAPTONE_LIB})
