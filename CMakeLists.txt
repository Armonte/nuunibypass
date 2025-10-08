cmake_minimum_required(VERSION 3.10)
project(UNI2_DFolder_Bypass)

# Force 32-bit build
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")

# DLL that does the patching
add_library(bypass_dll SHARED bypass_dll.cpp)
target_link_libraries(bypass_dll)
set_target_properties(bypass_dll PROPERTIES PREFIX "")  # Remove 'lib' prefix
set_target_properties(bypass_dll PROPERTIES OUTPUT_NAME "bypass_dll")

# Launcher exe
add_executable(uni2_bypass_launcher launcher.cpp)

# Output to build directory
set_target_properties(bypass_dll PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set_target_properties(uni2_bypass_launcher PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Strip symbols for smaller files
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(bypass_dll PRIVATE -s)
    target_link_options(uni2_bypass_launcher PRIVATE -s)
endif()

