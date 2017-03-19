cmake_minimum_required(VERSION 3.6)
project(PolyHook_2_0)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES MainTests.cpp PolyHook.h Catch.hpp UnitTests/ErrorSystem.cpp)
add_executable(PolyHook_2_0 ${SOURCE_FILES})
