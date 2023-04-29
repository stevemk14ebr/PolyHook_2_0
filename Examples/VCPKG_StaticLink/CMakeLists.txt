cmake_minimum_required(VERSION 3.3.0)
cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0091 NEW) 

project(test_polyhook2)

find_package(PolyHook_2 CONFIG REQUIRED)

set(CMAKE_CXX_FLAGS "/std:c++latest ${CMAKE_CXX_FLAGS}")

add_executable(test_polyhook2 main.cpp)
set_property(TARGET test_polyhook2 PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_link_libraries(test_polyhook2 PRIVATE PolyHook_2::PolyHook_2)
