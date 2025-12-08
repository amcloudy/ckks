cmake_minimum_required(VERSION 3.16)

project(ckks
    VERSION 0.1.0
    LANGUAGES CXX
)

# -----------------------------------------------------------
# Global configuration
# -----------------------------------------------------------

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(CKKS_BUILD_STATIC  "Build static CKKS library"          ON)
option(CKKS_BUILD_SHARED  "Build shared CKKS library"          ON)
option(CKKS_BUILD_TESTS   "Build CKKS unit tests"              ON)
option(CKKS_BUILD_BENCH   "Build CKKS benchmark executables"   ON)

# At least one of static / shared must be enabled
if(NOT CKKS_BUILD_STATIC AND NOT CKKS_BUILD_SHARED)
    message(FATAL_ERROR "At least one of CKKS_BUILD_STATIC or CKKS_BUILD_SHARED must be ON")
endif()

# -----------------------------------------------------------
# Sources
# -----------------------------------------------------------

file(GLOB_RECURSE CKKS_SOURCES
    src/core/*.cpp
    src/crypto/*.cpp
    src/utils/*.cpp
)

set(CKKS_PUBLIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# -----------------------------------------------------------
# Library targets
# -----------------------------------------------------------

set(CKKS_TARGETS "")   # list of libraries to install/export

# ---- static library ----------------------------------------------------------
if (CKKS_BUILD_STATIC)
    add_library(ckks_static STATIC ${CKKS_SOURCES})

    target_include_directories(ckks_static
        PUBLIC
            $<BUILD_INTERFACE:${CKKS_PUBLIC_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:include>
    )

    target_compile_definitions(ckks_static PRIVATE CKKS_BUILD_STATIC)

    # Installed artifact name: libckks.a
    set_target_properties(ckks_static PROPERTIES
        OUTPUT_NAME ckks
    )

    list(APPEND CKKS_TARGETS ckks_static)

    # Optional alias for consumers if they explicitly want static
    add_library(ckks::ckks_static ALIAS ckks_static)
endif()

# ---- shared library ----------------------------------------------------------
if (CKKS_BUILD_SHARED)
    add_library(ckks_shared SHARED ${CKKS_SOURCES})

    target_include_directories(ckks_shared
        PUBLIC
            $<BUILD_INTERFACE:${CKKS_PUBLIC_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:include>
    )

    target_compile_definitions(ckks_shared PRIVATE CKKS_BUILD_SHARED)

    # Installed artifact name: libckks.so (same name as static, different type)
    set_target_properties(ckks_shared PROPERTIES
        OUTPUT_NAME ckks
    )

    list(APPEND CKKS_TARGETS ckks_shared)

    add_library(ckks::ckks_shared ALIAS ckks_shared)
endif()

# ---- canonical imported target for consumers ---------------------------------
# Prefer shared if built, otherwise fall back to static.
if (CKKS_BUILD_SHARED)
    add_library(ckks::ckks ALIAS ckks_shared)
elseif (CKKS_BUILD_STATIC)
    add_library(ckks::ckks ALIAS ckks_static)
endif()

# -----------------------------------------------------------
# Installation + CMake package config
# -----------------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Install public headers
install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install libraries (only the ones that exist, via CKKS_TARGETS)
install(
    TARGETS ${CKKS_TARGETS}
    EXPORT ckksTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Export targets for find_package(ckks)
install(
    EXPORT ckksTargets
    FILE ckksTargets.cmake
    NAMESPACE ckks::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ckks
)

# Generate config file used by find_package(ckks)
configure_package_config_file(
    cmake/ckksConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ckksConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ckks
)

# Generate version file
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ckksConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install generated config + version files
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ckksConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/ckksConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ckks
)

# -----------------------------------------------------------
# Tests
# -----------------------------------------------------------

if (CKKS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# -----------------------------------------------------------
# Benchmarks
# -----------------------------------------------------------

if (CKKS_BUILD_BENCH)
    add_subdirectory(src/bench)
endif()
