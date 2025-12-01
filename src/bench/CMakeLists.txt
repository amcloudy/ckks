file(GLOB BENCH_SOURCES "*.cpp")

add_executable(ckks_bench ${BENCH_SOURCES})
target_link_libraries(ckks_bench PRIVATE ckks_static)

# Ensure benchmark executable is placed where build.sh expects
set_target_properties(ckks_bench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/bench
)
