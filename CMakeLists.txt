cmake_minimum_required(VERSION 3.16)
project(DPIEngine VERSION 2.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Author: Sachin Mishra
# DPI Engine - Deep Packet Inspection System

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Shared source files (used by both targets)
set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# ============================================================
# Target 1: Multi-threaded DPI Engine (MAIN - recommended)
# ============================================================
add_executable(dpi_engine
    src/dpi_mt.cpp
    ${SHARED_SOURCES}
)

# Enable threading for the multi-threaded version
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine Threads::Threads)

# ============================================================
# Target 2: Simple single-threaded version (for learning)
# ============================================================
add_executable(dpi_simple
    src/main_working.cpp
    ${SHARED_SOURCES}
)

# ============================================================
# Compiler-specific flags
# ============================================================
if(MSVC)
    # Visual Studio
    target_compile_options(dpi_engine PRIVATE /W4 /O2 /EHsc)
    target_compile_options(dpi_simple PRIVATE /W4 /O2 /EHsc)
else()
    # GCC / Clang
    target_compile_options(dpi_engine PRIVATE -Wall -Wextra -O2 -pthread)
    target_compile_options(dpi_simple PRIVATE -Wall -Wextra -O2)
    if(NOT APPLE)
        target_link_libraries(dpi_engine pthread)
    endif()
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(dpi_engine PRIVATE _WIN32_WINNT=0x0601)
    target_compile_definitions(dpi_simple PRIVATE _WIN32_WINNT=0x0601)
endif()

# ============================================================
# Install targets
# ============================================================
install(TARGETS dpi_engine dpi_simple
    RUNTIME DESTINATION bin
)

# Print build info
message(STATUS "=================================================")
message(STATUS "DPI Engine v2.0 by Sachin Mishra")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Targets: dpi_engine (multi-threaded), dpi_simple")
message(STATUS "=================================================")
