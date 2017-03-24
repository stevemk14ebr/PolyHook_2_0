cmake_minimum_required(VERSION 3.6)
project(PolyHook_2_0)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES MainTests.cpp src/PolyHook.h Catch.hpp UnitTests/ErrorSystem.cpp src/ADisassembler.hpp src/CapstoneDisassembler.hpp src/ErrorSystem.hpp UnitTests/Disassembler.cpp)

#Set this variable to hold the path to capstone directory
set(CAPSTONE_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/capstone)
#Find the absolute path to the lib
find_library(CAPSTONE_LIB NAMES libcapstone.a PATHS ${CAPSTONE_LIB_PATH})
add_executable(PolyHook_2_0 ${SOURCE_FILES})
#Link the capstone lib
target_link_libraries(${PROJECT_NAME} ${CAPSTONE_LIB})

message(STATUS ${CAPSTONE_LIB})

#copy lib to the built exe directory
#add_custom_command(TARGET PolyHook_2_0
 #       POST_BUILD
  #      COMMAND ${CMAKE_COMMAND} -E copy ${CAPSTONE_LIB} $<TARGET_FILE:PolyHook_2_0>)
