cmake_minimum_required(VERSION 3.15)

project(PolyHook_2)
string(TOLOWER ${PROJECT_NAME} LOWERCASE_PROJECT_NAME)
include(CMakePackageConfigHelpers)

if(WIN32)
	set(POLYHOOK_OS "windows")
elseif(APPLE)
	set(POLYHOOK_OS "macos")
elseif(UNIX)
	set(POLYHOOK_OS "linux")
endif()

#
# Options
#
option(POLYHOOK_BUILD_DLL "Build dll & lib instead of tests" ON)

option(POLYHOOK_BUILD_SHARED_LIB "Build polyhook2 as shared libary" OFF)
option(POLYHOOK_BUILD_SHARED_ASMTK "Build asmtk as shared libary" OFF)
option(POLYHOOK_BUILD_SHARED_ASMJIT "Build asmjit as shared libary" ${POLYHOOK_BUILD_SHARED_ASMTK})
option(POLYHOOK_BUILD_SHARED_ZYDIS "Build zydis as shared libary" OFF)

option(POLYHOOK_USE_EXTERNAL_ASMTK "Use external asmtk libary" OFF)
option(POLYHOOK_USE_EXTERNAL_ASMJIT "Use external asmjit libary" ${POLYHOOK_USE_EXTERNAL_ASMTK})
option(POLYHOOK_USE_EXTERNAL_ZYDIS "Use external zydis libary" OFF)

if(MSVC)
	option(POLYHOOK_BUILD_STATIC_RUNTIME "Use static runtime" ON)
endif()

if(WIN32)
    option(POLYHOOK_FEATURE_EXCEPTION "Implement all exception hooking functionality" ON)
    option(POLYHOOK_FEATURE_PE "Implement all win pe hooking functionality" ON)
else()
    set(POLYHOOK_FEATURE_EXCEPTION OFF)
    set(POLYHOOK_FEATURE_PE OFF)
endif()
option(POLYHOOK_FEATURE_DETOURS "Implement detour functionality" ON)
option(POLYHOOK_FEATURE_INLINENTD "Support inline hooks without specifying typedefs by generating callback stubs at runtime with AsmJit" ON)
option(POLYHOOK_FEATURE_VIRTUALS "Implement all virtual table hooking functionality" ON)

#
# ASMTK
#

function(add_asmjit_properties)
    if(MSVC)
        if(POLYHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()
endfunction()

if(POLYHOOK_FEATURE_DETOURS AND NOT POLYHOOK_USE_EXTERNAL_ASMTK)
	if(NOT POLYHOOK_USE_EXTERNAL_ASMJIT)
	    set(ASMJIT_DIR "${PROJECT_SOURCE_DIR}/asmjit")
    endif()
	# asmjit and asmtk do not use `option`
	if(POLYHOOK_BUILD_SHARED_ASMTK)
		set(ASMTK_STATIC OFF)
		set(ASMJIT_STATIC OFF)
    else()
		set(ASMTK_STATIC ON)
		set(ASMJIT_STATIC ON)
    endif()

    add_subdirectory(asmtk)
    add_asmjit_properties()

	if(MSVC)
		if(POLYHOOK_BUILD_STATIC_RUNTIME)
			set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
		else()
			set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
		endif()
	endif()

endif()

#
# ASMJIT
#

if(POLYHOOK_FEATURE_INLINENTD AND NOT POLYHOOK_USE_EXTERNAL_ASMJIT)
    # Avoid including asmjit again if it was already included
    if(NOT TARGET asmjit)
        # asmjit doesn't use `option`
        if(POLYHOOK_BUILD_SHARED_ASMJIT)
            set(ASMJIT_STATIC OFF)
        else()
            set(ASMJIT_STATIC ON)
        endif()

	add_subdirectory(asmjit)
        add_asmjit_properties()
    endif()
endif()

#
# Zydis
#

function(set_zycore_options)
	set(ZYCORE_BUILD_SHARED_LIB ${POLYHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "" FORCE)
	set(ZYCORE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
endfunction()

function(set_zydis_options)
	set(ZYDIS_BUILD_SHARED_LIB ${POLYHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
endfunction()

if(NOT POLYHOOK_USE_EXTERNAL_ZYDIS)
	set_zycore_options()
	add_subdirectory(zydis/dependencies/zycore)
	set_zydis_options()
	add_subdirectory(zydis)

	if(MSVC)
		if(POLYHOOK_BUILD_STATIC_RUNTIME)
			set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
			set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
		else()
			set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
			set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
		endif()
	endif()
endif()

#
# Polyhook
#

if(POLYHOOK_BUILD_DLL)
	if(POLYHOOK_BUILD_SHARED_LIB)
		add_library(${PROJECT_NAME} SHARED)
		set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
	else()
		add_library(${PROJECT_NAME} STATIC)
	endif()
else()
	add_executable(${PROJECT_NAME})
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON)

if(MSVC)
    if(POLYHOOK_BUILD_STATIC_RUNTIME)
		set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	else()
		set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
	endif()

	if(MSVC)
		  set(COMPILE_FLAGS_PLH "/W4 /Z7")
		  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
			set(COMPILE_FLAGS_PLH "/MP ${COMPILE_FLAGS_PLH}")
		  endif()

		  set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${COMPILE_FLAGS_PLH})
		  target_link_libraries(${PROJECT_NAME} PRIVATE optimized -DEBUG) # mhhm ya pdbs
	endif()

endif()

target_include_directories(${PROJECT_NAME}
    PUBLIC
		$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    INTERFACE
		$<INSTALL_INTERFACE:include>
)

#Core
set(POLYHOOK_CORE_HEADERS
        ${PROJECT_SOURCE_DIR}/polyhook2/Enums.hpp
        ${PROJECT_SOURCE_DIR}/polyhook2/IHook.hpp
        ${PROJECT_SOURCE_DIR}/polyhook2/Instruction.hpp
        ${PROJECT_SOURCE_DIR}/polyhook2/Misc.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/UID.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/ErrorLog.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/MemProtector.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/MemAccessor.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/FBAllocator.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/RangeAllocator.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Tests/TestEffectTracker.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Tests/StackCanary.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/EventDispatcher.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/PolyHookOs.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/PolyHookOsIncludes.hpp
		)
install(FILES ${POLYHOOK_CORE_HEADERS} DESTINATION include/polyhook2)


target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/MemProtector.cpp
	${PROJECT_SOURCE_DIR}/sources/MemAccessor.cpp
	${PROJECT_SOURCE_DIR}/sources/TestEffectTracker.cpp
	${PROJECT_SOURCE_DIR}/sources/StackCanary.cpp
	${PROJECT_SOURCE_DIR}/sources/FBAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/RangeAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/ErrorLog.cpp
	${PROJECT_SOURCE_DIR}/sources/UID.cpp
	${PROJECT_SOURCE_DIR}/sources/Misc.cpp
	${PROJECT_SOURCE_DIR}/sources/PolyHookOs.cpp
	)

if(NOT POLYHOOK_BUILD_DLL)
	target_compile_options(${PROJECT_NAME} PRIVATE
		$<$<BOOL:${UNIX}>:-fpermissive>
	)
endif()

#DisAsm/Zydis
if (POLYHOOK_USE_EXTERNAL_ZYDIS)
    find_library(ZYDIS_LIBRARY NAMES Zydis)
    find_library(ZYCORE_LIBRARY NAMES Zycore)
    find_path(ZYDIS_INCLUDE_DIR NAMES Zydis/Zydis.h)
    find_path(ZYCORE_INCLUDE_DIR NAMES Zycore/Zycore.h)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYDIS_LIBRARY})
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYCORE_LIBRARY})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYDIS_INCLUDE_DIR})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYCORE_INCLUDE_DIR})
	find_package(zydis REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC Zydis::Zydis)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:Zydis>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/dependencies/zycore/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/zydis>)
endif()

target_sources(${PROJECT_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/sources/ZydisDisassembler.cpp")
install(FILES ${PROJECT_SOURCE_DIR}/polyhook2/ZydisDisassembler.hpp DESTINATION include/polyhook2)

function(link_asmjit)
    if (POLYHOOK_USE_EXTERNAL_ASMJIT)
        find_library(ASMJIT_LIBRARY NAMES asmjit)
        find_path(ASMJIT_INCLUDE_DIR NAMES asmjit/asmjit.h)
        target_link_libraries(${PROJECT_NAME} PRIVATE ${ASMJIT_LIBRARY})
        target_include_directories(${PROJECT_NAME} PUBLIC ${ASMJIT_INCLUDE_DIR})
		find_package(asmjit REQUIRED)
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmjit)
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:asmjit>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMJIT_SRC}>")
    endif()
endfunction()

#Feature/Detours
if(POLYHOOK_FEATURE_DETOURS)
    link_asmjit()

    if (POLYHOOK_USE_EXTERNAL_ASMTK)
        find_library(ASMTK_LIBRARY NAMES asmtk)
        find_path(ASMTK_INCLUDE_DIR NAMES asmtk/asmtk.h)
        target_link_libraries(${PROJECT_NAME} PUBLIC ${ASMTK_LIBRARY})
        target_include_directories(${PROJECT_NAME} PUBLIC ${ASMTK_INCLUDE_DIR})
		find_package(asmtk REQUIRED)
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmtk)
    else()
        target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:asmtk>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMTK_SRC}>")
    endif()

	set(POLYHOOK_DETOUR_HEADERS
		${PROJECT_SOURCE_DIR}/polyhook2/Detour/ADetour.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Detour/NatDetour.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Detour/x64Detour.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Detour/x86Detour.hpp)

	install(FILES ${POLYHOOK_DETOUR_HEADERS} DESTINATION include/polyhook2/Detour)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
		${PROJECT_SOURCE_DIR}/sources/x64Detour.cpp
		${PROJECT_SOURCE_DIR}/sources/x86Detour.cpp)

	# only build tests if making exe
	if(NOT POLYHOOK_BUILD_DLL)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8) #64-bit
			target_sources(${PROJECT_NAME} PRIVATE
			    ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourx64.cpp
			    ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourTranslationx64.cpp
				${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourSchemex64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4) #32-bit
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourx86.cpp)
		endif()
	endif()
endif()

#Feature/Inlinentd
if(POLYHOOK_FEATURE_INLINENTD)
    link_asmjit()

	install(FILES ${PROJECT_SOURCE_DIR}/polyhook2/Detour/ILCallback.hpp DESTINATION include/polyhook2/Detour)

	target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/sources/ILCallback.cpp)

	# only build tests if making exe
	if(NOT POLYHOOK_BUILD_DLL)
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourNoTDx64.cpp)
		elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
			target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDetourNoTDx86.cpp)
		endif()
	endif()
endif()

#Feature/Exception
if(POLYHOOK_FEATURE_EXCEPTION)
    set(POLYHOOK_EXCEPTION_HEADERS
        ${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/AVehHook.hpp
        ${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/BreakPointHook.hpp
        ${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/HWBreakPointHook.hpp)
    install(FILES ${POLYHOOK_EXCEPTION_HEADERS} DESTINATION include/polyhook2/Exceptions)

    target_sources(${PROJECT_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}/sources/AVehHook.cpp
        ${PROJECT_SOURCE_DIR}/sources/BreakPointHook.cpp
        ${PROJECT_SOURCE_DIR}/sources/HWBreakPointHook.cpp)

    # only build tests if making exe
    if(NOT POLYHOOK_BUILD_DLL)
        target_sources(${PROJECT_NAME} PRIVATE
            ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestBreakpointHook.cpp
            ${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestHWBreakpointHook.cpp)
    endif()
endif()

#Feature/PE
if(POLYHOOK_FEATURE_PE)
	set(POLYHOOK_PE_HEADERS
		${PROJECT_SOURCE_DIR}/polyhook2/PE/EatHook.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/PE/IatHook.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/PE/PEB.hpp)
	install(FILES ${POLYHOOK_PE_HEADERS} DESTINATION include/polyhook2/PE)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/EatHook.cpp
		${PROJECT_SOURCE_DIR}/sources/IatHook.cpp)

	# only build tests if making exe
	if(NOT POLYHOOK_BUILD_DLL)
		target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestEatHook.cpp
			${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestIatHook.cpp)
	endif()
endif()


#Feature/Virtuals
if(POLYHOOK_FEATURE_VIRTUALS)
	set(POLYHOOK_VIRTUAL_HEADERS
		${PROJECT_SOURCE_DIR}/polyhook2/Virtuals/VTableSwapHook.hpp
		${PROJECT_SOURCE_DIR}/polyhook2/Virtuals/VFuncSwapHook.hpp)
	install(FILES ${POLYHOOK_VIRTUAL_HEADERS} DESTINATION include/polyhook2/Virtuals)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/sources/VTableSwapHook.cpp
		${PROJECT_SOURCE_DIR}/sources/VFuncSwapHook.cpp)

	# only build tests if making exe
	if(NOT POLYHOOK_BUILD_DLL)
		target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestVTableSwapHook.cpp
			
			${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestVFuncSwapHook.cpp)
	endif()
endif()


#Tests
if(NOT POLYHOOK_BUILD_DLL)
	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/MainTests.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestDisassembler.cpp
		${PROJECT_SOURCE_DIR}/UnitTests/${POLYHOOK_OS}/TestMemProtector.cpp)
endif()


#
# Install
#

configure_package_config_file(
		"${LOWERCASE_PROJECT_NAME}-config.cmake.in"
		"${LOWERCASE_PROJECT_NAME}-config.cmake"
	INSTALL_DESTINATION
        "lib/${PROJECT_NAME}"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${LOWERCASE_PROJECT_NAME}-config.cmake"
    DESTINATION
        "lib/${PROJECT_NAME}"
)

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    RUNTIME DESTINATION "bin"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
)

install(
    EXPORT
        ${PROJECT_NAME}-targets
    NAMESPACE
        ${PROJECT_NAME}::
    DESTINATION
        "lib/${PROJECT_NAME}"
)
