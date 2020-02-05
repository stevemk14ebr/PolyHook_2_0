# CMakeList.txt : CMake project for ExampleProject, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (ExampleProject "ExampleProject.cpp" "ExampleProject.h")

get_filename_component(PLH_DIR "../../../" ABSOLUTE)

include_directories(${PLH_DIR})

set(PLH_LIB_PATH_64 ${PLH_DIR}/build64)
set(PLH_LIB_PATH_86 ${PLH_DIR}/build32)
set(CAPSTONE_LIB_PATH_64 ${PLH_LIB_PATH_64}/capstone)
set(CAPSTONE_LIB_PATH_86 ${PLH_LIB_PATH_86}/capstone)

# add WALL + PDB flags
if(MSVC)
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

target_compile_options(${PROJECT_NAME} PRIVATE /std:c++latest)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
	
	#Link the capstone lib according to config mode
	target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_64}/Debug/capstone.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_64}/Release/capstone.lib)
	target_link_libraries(${PROJECT_NAME} debug ${PLH_LIB_PATH_64}/Debug/PolyHook_2.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${PLH_LIB_PATH_64}/Release/PolyHook_2.lib)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits

	#Link the capstone lib according to config mode
	target_link_libraries(${PROJECT_NAME} debug ${CAPSTONE_LIB_PATH_86}/Debug/capstone.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${CAPSTONE_LIB_PATH_86}/Release/capstone.lib)
	target_link_libraries(${PROJECT_NAME} debug ${PLH_LIB_PATH_86}/Debug/PolyHook_2.lib)
	target_link_libraries(${PROJECT_NAME} optimized ${PLH_LIB_PATH_86}/Release/PolyHook_2.lib)
endif()
# TODO: Add tests and install targets if needed.
