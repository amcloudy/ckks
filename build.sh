#!/usr/bin/env bash

set -e

# ============================
# Default Options
# ============================
BUILD_DIR="build"
BUILD_TYPE="Release"
BUILD_STATIC=ON
BUILD_SHARED=ON
BUILD_TESTS=ON
BUILD_BENCH=ON
RUN_TESTS=OFF
RUN_BENCH=OFF
INSTALL_PREFIX="/usr/local"

show_help() {
    echo "CKKS Build Script"
    echo ""
    echo "Usage: ./build.sh [options]"
    echo ""
    echo "Options:"
    echo "  --debug               Build in Debug mode (default: Release)"
    echo "  --release             Build in Release mode (default)"
    echo "  --static-only         Build only static library"
    echo "  --shared-only         Build only shared library"
    echo "  --no-tests            Disable unit tests"
    echo "  --no-bench            Disable benchmarks"
    echo "  --run-tests           Run tests after build"
    echo "  --run-bench           Run benchmarks after build"
    echo "  --clean               Remove build directory"
    echo "  --install [prefix]    Install library to prefix (default: /usr/local)"
    echo "  --help                Show this help message"
    echo ""
}

# ============================
# Parse Arguments
# ============================
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            ;;
        --release)
            BUILD_TYPE="Release"
            ;;
        --static-only)
            BUILD_STATIC=ON
            BUILD_SHARED=OFF
            ;;
        --shared-only)
            BUILD_STATIC=OFF
            BUILD_SHARED=ON
            ;;
        --no-tests)
            BUILD_TESTS=OFF
            ;;
        --no-bench)
            BUILD_BENCH=OFF
            ;;
        --run-tests)
            RUN_TESTS=ON
            ;;
        --run-bench)
            RUN_BENCH=ON
            ;;
        --clean)
            echo "Cleaning build directory..."
            rm -rf "${BUILD_DIR}"
            exit 0
            ;;
        --install)
            shift
            INSTALL_PREFIX="$1"
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

# ============================
# Configure Build Directory
# ============================
echo "======================================"
echo " CKKS Build Script"
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

# ============================
# Run CMake
# ============================
echo "Running CMake configuration..."

cmake .. \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCKKS_BUILD_STATIC=${BUILD_STATIC} \
    -DCKKS_BUILD_SHARED=${BUILD_SHARED} \
    -DCKKS_BUILD_TESTS=${BUILD_TESTS} \
    -DCKKS_BUILD_BENCH=${BUILD_BENCH} \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}

# ============================
# Build
# ============================
echo "Building CKKS library..."
cmake --build . -j$(nproc)

# ============================
# Optional: Run Tests
# ============================
if [[ "${RUN_TESTS}" == "ON" ]]; then
    echo "Running tests..."
    ctest --output-on-failure
fi

# ============================
# Optional: Run Benchmarks
# ============================
if [[ "${RUN_BENCH}" == "ON" ]]; then
    echo "Running benchmarks..."
    ./src/bench/ckks_bench
fi

# ============================
# Optional: Install
# ============================
if [[ "$INSTALL" == "ON" ]]; then
    echo "Installing library to ${INSTALL_PREFIX}..."
    cmake --install .
fi

echo "======================================"
echo " CKKS Build Complete"
echo "======================================"
