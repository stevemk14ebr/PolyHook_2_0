cmake_minimum_required(VERSION 3.6)
project(PolyHook_2)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

#IDE's like it when header file are included as source files
set(HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/ADisassembler.hpp
        ${PROJECT_SOURCE_DIR}/headers/CapstoneDisassembler.hpp
        ${PROJECT_SOURCE_DIR}/headers/Enums.hpp
        ${PROJECT_SOURCE_DIR}/headers/IHook.hpp
        ${PROJECT_SOURCE_DIR}/headers/Instruction.hpp
        ${PROJECT_SOURCE_DIR}/headers/Misc.hpp
       )

set(DETOUR_HEADER_FILES ${PROJECT_SOURCE_DIR}/headers/Detour/ADetour.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x64DetourImp.hpp
        ${PROJECT_SOURCE_DIR}/headers/Detour/x86DetourImp.hpp)

#TODO: Setup source groups using the header file variables above

include_directories(${PROJECT_SOURCE_DIR})

set(UNIT_TEST_SOURCES ${PROJECT_SOURCE_DIR}/MainTests.cpp
        ${PROJECT_SOURCE_DIR}/UnitTests/TestDisassembler.cpp)

set(HEADER_IMP_SOURCES ${PROJECT_SOURCE_DIR}/sources/CapstoneDisassembler.cpp
        ${PROJECT_SOURCE_DIR}/sources/x64DetourImp.cpp
        ${PROJECT_SOURCE_DIR}/sources/x86DetourImp.cpp)

set(SOURCE_FILES_PLH ${UNIT_TEST_SOURCES} ${HEADER_IMP_SOURCES} ${HEADER_FILES} ${DETOUR_HEADER_FILES})

add_executable(PolyHook_2 ${SOURCE_FILES_PLH})
set_target_properties(PolyHook_2 PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${EXECUTABLE_OUTPUT_PATH}")

#Set this variable to hold the path to capstone directory
set(CAPSTONE_LIB_PATH_64 ${PROJECT_SOURCE_DIR}/capstone/build64/)
set(CAPSTONE_LIB_PATH_86 ${PROJECT_SOURCE_DIR}/capstone/build/)

#Find the absolute path to the lib (linux)
#find_library(CAPSTONE_LIB NAMES libcapstone.a PATHS ${CAPSTONE_LIB_PATH})

#Link the capstone lib according to config mode
target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_86}/Debug/capstone.lib)
target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_86}/Release/capstone.lib)

