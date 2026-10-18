# The C++ binding of the sans-I/O C2PA reader and builder: a Rust static library
# behind a C ABI, with header-only readers and compiled signing/thread pools.
#
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
#
# Options:
#   BUILD_TESTING=OFF    Build the library and examples without GoogleTest
#   C2PA_SM_FETCH_GTEST=ON  Download pinned GoogleTest instead of requiring a package
#   C2PA_SM_COVERAGE=ON   gcc/clang source coverage of the C++ (see CI)
#   C2PA_SM_SANITIZE=...  "address" or "thread" (Rust side stays uninstrumented)
cmake_minimum_required(VERSION 3.16)
project(contentauth_c2pa_cpp LANGUAGES CXX)

# Keep every generated file out of the source tree; build with `-B build`.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not supported. Use: cmake -S . -B build")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

option(C2PA_SM_COVERAGE "Instrument the C++ for coverage" OFF)
option(C2PA_SM_FETCH_GTEST "Allow downloading pinned GoogleTest when no package is installed" OFF)
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
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wdangling-else -Werror)
  if(C2PA_SM_COVERAGE)
    if(NOT "${ARGV1}" STREQUAL "NO_COVERAGE")
      target_compile_options(${target} PRIVATE --coverage -fprofile-update=atomic -O0 -g)
    endif()
    target_link_options(${target} PRIVATE --coverage)
  endif()
  if(C2PA_SM_SANITIZE)
    target_compile_options(${target} PRIVATE -fsanitize=${C2PA_SM_SANITIZE} -fno-omit-frame-pointer -g)
    target_link_options(${target} PRIVATE -fsanitize=${C2PA_SM_SANITIZE})
  endif()
endfunction()

# ---- the C++ library --------------------------------------------------------
# The signing implementation and thread pools are compiled; reader drivers
# stay header-only. Clients see `include/`; `cpp/include/` is private.
set(C2PA_SM_CPP_SOURCES cpp/src/simple_thread_pool.cpp cpp/src/sign.cpp cpp/src/sign_async.cpp)
if(APPLE)
  list(APPEND C2PA_SM_CPP_SOURCES cpp/src/apple_thread_pool.cpp)
endif()
add_library(c2pa_sm_cpp STATIC ${C2PA_SM_CPP_SOURCES})
target_include_directories(c2pa_sm_cpp
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cpp/include")
target_link_libraries(c2pa_sm_cpp PUBLIC c2pa_sm)
set_target_properties(c2pa_sm_cpp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_cpp)

add_library(c2pa_sm_coro STATIC cpp/src/sign_coro.cpp)
target_link_libraries(c2pa_sm_coro PUBLIC c2pa_sm_cpp)
target_compile_features(c2pa_sm_coro PUBLIC cxx_std_20)
set_target_properties(c2pa_sm_coro PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_coro)

# ---- tests and examples -----------------------------------------------------
include(CTest)
set(FIXTURE "${WORKSPACE_ROOT}/contentauth-c2pa-reader/tests/fixtures/C.jpg")

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${WORKSPACE_ROOT}/contentauth-c2pa-sign-baseline/src/definition.rs")
file(READ "${WORKSPACE_ROOT}/contentauth-c2pa-sign-baseline/src/definition.rs" SIGN_DEFINITION_SOURCE)
string(REGEX MATCH "pub const BASELINE_DEFINITION: &str = r#\"[^#]*\"#;" SIGN_DEFINITION "${SIGN_DEFINITION_SOURCE}")
string(REGEX REPLACE "^pub const BASELINE_DEFINITION: &str = r#\"|\"#;$" "" SIGN_DEFINITION "${SIGN_DEFINITION}")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/signing-definition.json" CONTENT "${SIGN_DEFINITION}")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/fixtures.hpp" CONTENT
"#pragma once
inline constexpr char signing_definition[] = R\"json(${SIGN_DEFINITION})json\";
inline constexpr char signing_cert_path[] = \"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.der\";
inline constexpr char signing_key_path[] = \"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem\";
")

if(BUILD_TESTING)
  find_package(GTest 1.17 CONFIG QUIET)
  if(NOT GTest_FOUND)
    if(NOT C2PA_SM_FETCH_GTEST)
      message(FATAL_ERROR
        "GoogleTest >= 1.17 is required for tests. Set GTest_DIR or CMAKE_PREFIX_PATH "
        "to an installed package, explicitly allow a download with "
        "-DC2PA_SM_FETCH_GTEST=ON, or disable tests with -DBUILD_TESTING=OFF.")
    endif()
    include(FetchContent)
    if(POLICY CMP0135)
      cmake_policy(SET CMP0135 NEW)
    endif()
    set(BUILD_GMOCK OFF)
    set(INSTALL_GTEST OFF)
    FetchContent_Declare(googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.18.0.tar.gz
      URL_HASH SHA256=6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5)
    FetchContent_MakeAvailable(googletest)
  endif()

  add_executable(c2pa_sm_tests
    cpp/tests/tests_cxx17.cpp
    cpp/tests/tests_sign_async.cpp
    cpp/tests/tests_pool.cpp
    cpp/tests/tests_cxx20.cpp
    cpp/tests/tests_assertions.cpp)
  target_link_libraries(c2pa_sm_tests PRIVATE c2pa_sm_coro GTest::gtest_main OpenSSL::Crypto)
  target_include_directories(c2pa_sm_tests PRIVATE cpp/include "${CMAKE_CURRENT_BINARY_DIR}")
  set_target_properties(c2pa_sm_tests PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
  target_compile_definitions(c2pa_sm_tests PRIVATE C2PA_SM_FIXTURE="${FIXTURE}")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(c2pa_sm_tests PRIVATE cpp/tests/tests_sign_posix.cpp)
    target_link_options(c2pa_sm_tests PRIVATE
      -Wl,--wrap=pread -Wl,--wrap=pwrite -Wl,--wrap=fstat -Wl,--wrap=fsync)
  endif()
  if(C2PA_SM_COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_definitions(c2pa_sm_tests PRIVATE C2PA_SM_GCOV=1)
  endif()
  c2pa_sm_target_flags(c2pa_sm_tests)
  include(GoogleTest)
  gtest_discover_tests(c2pa_sm_tests TEST_PREFIX "cpp." PROPERTIES TIMEOUT 120)

  add_executable(c2pa_sm_cxx17_check cpp/tests/compile_cxx17.cpp)
  target_link_libraries(c2pa_sm_cxx17_check PRIVATE c2pa_sm_cpp)
  set_target_properties(c2pa_sm_cxx17_check PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
  # Build/link only: never run or add unexecuted header counters to coverage.
  c2pa_sm_target_flags(c2pa_sm_cxx17_check NO_COVERAGE)
endif()

add_subdirectory(examples)
