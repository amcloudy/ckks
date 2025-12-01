cmake_minimum_required(VERSION 3.16)
project(ckks VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(CKKS_BUILD_STATIC "Build static library" ON)
option(CKKS_BUILD_SHARED "Build shared library" ON)
option(CKKS_BUILD_TESTS  "Build unit tests" ON)
option(CKKS_BUILD_BENCH  "Build benchmarks" ON)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Core + Crypto sources
file(GLOB_RECURSE CKKS_SOURCES
        "src/core/*.cpp"
        "src/crypto/*.cpp"
)

# ===== LIBRARIES =====
if(CKKS_BUILD_STATIC)
    add_library(ckks_static STATIC ${CKKS_SOURCES})
    set_target_properties(ckks_static PROPERTIES OUTPUT_NAME ckks)
endif()

if(CKKS_BUILD_SHARED)
    add_library(ckks_shared SHARED ${CKKS_SOURCES})
    set_target_properties(ckks_shared PROPERTIES OUTPUT_NAME ckks)
endif()

# ===== TESTS =====
if(CKKS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ===== BENCHMARKS =====
if(CKKS_BUILD_BENCH)
    add_subdirectory(src/bench)
endif()
