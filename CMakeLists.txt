cmake_minimum_required(VERSION 3.19)
project(jdevtools)


set(CMAKE_CXX_STANDARD 17)


# Define the static library
add_library(jdevtools INTERFACE) ## if header only
# file(GLOB_RECURSE MY_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
# add_library(jdevtools STATIC ${MY_SOURCES})


# Set include directories. INTERFACE if no source file, else PUBLIC
target_include_directories(jdevtools INTERFACE 
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)


# Glob all pre-compiled .lib files in the lib directory if header only library with binary
# file(GLOB LIB_FILES "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.lib")
# target_link_libraries(jdevtools INTERFACE ${LIB_FILES})