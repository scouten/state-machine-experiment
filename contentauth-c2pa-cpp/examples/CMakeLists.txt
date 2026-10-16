# The examples build the way a client of the library would: they see only the
# public `c2pa_sm_cpp` target, and so only `include/`.

add_executable(c2pa_sm_read read.cpp)
target_link_libraries(c2pa_sm_read PRIVATE c2pa_sm_cpp)
set_target_properties(c2pa_sm_read PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_read)
add_test(NAME example_read COMMAND c2pa_sm_read "${FIXTURE}")

add_executable(c2pa_sm_parallel parallel.cpp)
target_link_libraries(c2pa_sm_parallel PRIVATE c2pa_sm_cpp)
set_target_properties(c2pa_sm_parallel PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_parallel)
add_test(NAME example_parallel COMMAND c2pa_sm_parallel "${FIXTURE}")
