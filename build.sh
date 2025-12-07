#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# Default Options
# ============================================================

BUILD_DIR="build"
BUILD_TYPE="Release"
BUILD_STATIC=ON
BUILD_SHARED=ON
BUILD_TESTS=ON
BUILD_BENCH=ON
RUN_TESTS=OFF
RUN_BENCH=OFF
DO_INSTALL=OFF
INSTALL_PREFIX="/usr/local"

show_help() {
    cat <<EOF
CKKS Build Script

Usage: ./build.sh [options]

Options:
  --debug               Build in Debug mode
  --release             Build in Release mode (default)
  --static-only         Build only static library
  --shared-only         Build only shared library
  --no-tests            Disable unit tests
  --no-bench            Disable benchmarks
  --run-tests           Run ctest after build
  --run-bench           Run benchmark executables after build
  --clean               Delete build directory and exit
  --install [prefix]    Install CKKS library (default prefix: /usr/local)
  --help                Show this help message
EOF
}

# ============================================================
# Parse Arguments
# ============================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug) BUILD_TYPE="Debug" ;;
        --release) BUILD_TYPE="Release" ;;
        --static-only) BUILD_STATIC=ON; BUILD_SHARED=OFF ;;
        --shared-only) BUILD_STATIC=OFF; BUILD_SHARED=ON ;;
        --no-tests) BUILD_TESTS=OFF ;;
        --no-bench) BUILD_BENCH=OFF ;;
        --run-tests) RUN_TESTS=ON ;;
        --run-bench) RUN_BENCH=ON ;;
        --clean)
            echo "Cleaning build directory..."
            rm -rf "${BUILD_DIR}"
            exit 0
            ;;
        --install)
            DO_INSTALL=ON
            shift
            INSTALL_PREFIX="${1:-/usr/local}"
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# ============================================================
# Summary
# ============================================================

echo "======================================"
echo " CKKS Build Configuration"
echo "======================================"
echo "Build Type      : ${BUILD_TYPE}"
echo "Static Library  : ${BUILD_STATIC}"
echo "Shared Library  : ${BUILD_SHARED}"
echo "Build Tests     : ${BUILD_TESTS}"
echo "Build Bench     : ${BUILD_BENCH}"
echo "Install Prefix  : ${INSTALL_PREFIX}"
echo "======================================"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# ============================================================
# Configure CMake
# ============================================================

echo "Configuring CMake..."

cmake .. \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCKKS_BUILD_STATIC="${BUILD_STATIC}" \
    -DCKKS_BUILD_SHARED="${BUILD_SHARED}" \
    -DCKKS_BUILD_TESTS="${BUILD_TESTS}" \
    -DCKKS_BUILD_BENCH="${BUILD_BENCH}" \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}"

# ============================================================
# Build
# ============================================================

echo "Building CKKS..."
cmake --build . -j"$(nproc)"

# ============================================================
# Tests
# ============================================================

if [[ "${RUN_TESTS}" == "ON" ]]; then
    echo "Running tests..."
    ctest --output-on-failure
fi

# ============================================================
# Benchmarks
# ============================================================

if [[ "${RUN_BENCH}" == "ON" ]]; then
    echo "Running benchmarks..."
    ./src/bench/ckks_bench
fi

# ============================================================
# Install
# ============================================================

if [[ "${DO_INSTALL}" == "ON" ]]; then
    echo "Installing CKKS to ${INSTALL_PREFIX}..."
    cmake --install .
fi

echo "======================================"
echo " CKKS Build Complete"
echo "======================================"
