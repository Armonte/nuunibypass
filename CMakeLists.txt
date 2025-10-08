cmake_minimum_required(VERSION 3.10)
project(UNI2_DFolder_Bypass)

# Force 32-bit build
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")

# WinMM Proxy DLL
add_library(winmm SHARED winmm.cpp winmm.def)
target_link_libraries(winmm kernel32)
set_target_properties(winmm PROPERTIES PREFIX "")  # Remove 'lib' prefix
set_target_properties(winmm PROPERTIES OUTPUT_NAME "winmm")

# Output to build directory
set_target_properties(winmm PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Strip symbols for smaller files
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(winmm PRIVATE -s -static-libgcc -static-libstdc++)
endif()

# Create steam_appid.txt
file(WRITE ${CMAKE_BINARY_DIR}/steam_appid.txt "2076010")

