# The C++ binding of the sans-I/O C2PA reader: a Rust static library behind a
# C ABI (built here with cargo), and header-only C++ on top.
#
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
#
# Options:
#   C2PA_SM_COVERAGE=ON   gcc/clang source coverage of the C++ (see CI)
#   C2PA_SM_SANITIZE=...  "address" or "thread" (Rust side stays uninstrumented)
cmake_minimum_required(VERSION 3.16)
project(contentauth_c2pa_cpp LANGUAGES CXX)

option(C2PA_SM_COVERAGE "Instrument the C++ for coverage" OFF)
set(C2PA_SM_SANITIZE "" CACHE STRING "Sanitizer for the C++ code: address or thread")

find_package(Threads REQUIRED)
find_program(CARGO cargo REQUIRED)

# ---- the Rust library -------------------------------------------------------
get_filename_component(WORKSPACE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo")
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CARGO_PROFILE_DIR release)
  set(CARGO_PROFILE_ARG --release)
else()
  set(CARGO_PROFILE_DIR debug)
  set(CARGO_PROFILE_ARG "")
endif()
set(C2PA_SM_STATIC_LIB "${CARGO_TARGET_DIR}/${CARGO_PROFILE_DIR}/libcontentauth_c2pa_cpp.a")

add_custom_target(c2pa_sm_rust
  COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
          ${CARGO} build --manifest-path "${WORKSPACE_ROOT}/Cargo.toml"
          -p contentauth-c2pa-cpp ${CARGO_PROFILE_ARG}
  BYPRODUCTS "${C2PA_SM_STATIC_LIB}"
  USES_TERMINAL
  COMMENT "cargo build -p contentauth-c2pa-cpp")

add_library(c2pa_sm STATIC IMPORTED GLOBAL)
set_target_properties(c2pa_sm PROPERTIES
  IMPORTED_LOCATION "${C2PA_SM_STATIC_LIB}"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
  INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS};m")
add_dependencies(c2pa_sm c2pa_sm_rust)

# ---- flags for the C++ ------------------------------------------------------
function(c2pa_sm_target_flags target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(C2PA_SM_COVERAGE)
    target_compile_options(${target} PRIVATE --coverage -fprofile-update=atomic -O0 -g)
    target_link_options(${target} PRIVATE --coverage)
  endif()
  if(C2PA_SM_SANITIZE)
    target_compile_options(${target} PRIVATE -fsanitize=${C2PA_SM_SANITIZE} -fno-omit-frame-pointer -g)
    target_link_options(${target} PRIVATE -fsanitize=${C2PA_SM_SANITIZE})
  endif()
endfunction()

# ---- tests and examples -----------------------------------------------------
enable_testing()
set(FIXTURE "${WORKSPACE_ROOT}/contentauth-c2pa-reader/tests/fixtures/C.jpg")

# The core and the thread-based drivers must stay C++17.
add_executable(c2pa_sm_tests_cxx17 cpp/tests/tests_cxx17.cpp)
target_link_libraries(c2pa_sm_tests_cxx17 PRIVATE c2pa_sm)
target_compile_features(c2pa_sm_tests_cxx17 PRIVATE cxx_std_17)
set_target_properties(c2pa_sm_tests_cxx17 PROPERTIES CXX_STANDARD 17 CXX_EXTENSIONS OFF)
target_compile_definitions(c2pa_sm_tests_cxx17 PRIVATE C2PA_SM_FIXTURE="${FIXTURE}")
c2pa_sm_target_flags(c2pa_sm_tests_cxx17)
add_test(NAME cxx17 COMMAND c2pa_sm_tests_cxx17)

add_executable(c2pa_sm_tests_cxx20 cpp/tests/tests_cxx20.cpp)
target_link_libraries(c2pa_sm_tests_cxx20 PRIVATE c2pa_sm)
set_target_properties(c2pa_sm_tests_cxx20 PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_compile_definitions(c2pa_sm_tests_cxx20 PRIVATE C2PA_SM_FIXTURE="${FIXTURE}")
c2pa_sm_target_flags(c2pa_sm_tests_cxx20)
add_test(NAME cxx20 COMMAND c2pa_sm_tests_cxx20)

add_executable(c2pa_sm_read cpp/examples/read.cpp)
target_link_libraries(c2pa_sm_read PRIVATE c2pa_sm)
set_target_properties(c2pa_sm_read PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_read)
add_test(NAME example_read COMMAND c2pa_sm_read "${FIXTURE}")

add_executable(c2pa_sm_parallel cpp/examples/parallel.cpp)
target_link_libraries(c2pa_sm_parallel PRIVATE c2pa_sm)
set_target_properties(c2pa_sm_parallel PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_parallel)
add_test(NAME example_parallel COMMAND c2pa_sm_parallel "${FIXTURE}")
