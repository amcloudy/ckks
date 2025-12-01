file(GLOB TEST_SOURCES "*.cpp")

add_executable(ckks_tests ${TEST_SOURCES})
target_link_libraries(ckks_tests PRIVATE ckks_static)
add_test(NAME ckks_unit_tests COMMAND ckks_tests)
