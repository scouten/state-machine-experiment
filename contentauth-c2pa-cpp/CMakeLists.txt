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

# Keep every generated file out of the source tree; build with `-B build`.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not supported. Use: cmake -S . -B build")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

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

# ---- the C++ library --------------------------------------------------------
# The signing implementation and thread pools are compiled; reader drivers
# stay header-only. Clients see `include/`; `cpp/include/` is private.
set(C2PA_SM_CPP_SOURCES cpp/src/simple_thread_pool.cpp cpp/src/sign.cpp)
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

# ---- tests and examples -----------------------------------------------------
enable_testing()
set(FIXTURE "${WORKSPACE_ROOT}/contentauth-c2pa-reader/tests/fixtures/C.jpg")

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${WORKSPACE_ROOT}/contentauth-c2pa-sign-baseline/src/definition.rs")
file(READ "${WORKSPACE_ROOT}/contentauth-c2pa-sign-baseline/src/definition.rs" SIGN_DEFINITION_SOURCE)
string(REGEX MATCH "pub const BASELINE_DEFINITION: &str = r#\"[^#]*\"#;" SIGN_DEFINITION "${SIGN_DEFINITION_SOURCE}")
string(REGEX REPLACE "^pub const BASELINE_DEFINITION: &str = r#\"|\"#;$" "" SIGN_DEFINITION "${SIGN_DEFINITION}")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/fixtures.hpp" CONTENT
"#pragma once
inline constexpr char signing_definition[] = R\"json(${SIGN_DEFINITION})json\";
inline constexpr char signing_cert_path[] = \"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.der\";
inline constexpr char signing_key_path[] = \"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem\";
")

# The core and the thread-based drivers must stay C++17.
add_executable(c2pa_sm_tests_cxx17 cpp/tests/tests_cxx17.cpp)
target_link_libraries(c2pa_sm_tests_cxx17 PRIVATE c2pa_sm_cpp OpenSSL::Crypto)
target_include_directories(c2pa_sm_tests_cxx17 PRIVATE cpp/include "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_features(c2pa_sm_tests_cxx17 PRIVATE cxx_std_17)
set_target_properties(c2pa_sm_tests_cxx17 PROPERTIES CXX_STANDARD 17 CXX_EXTENSIONS OFF)
target_compile_definitions(c2pa_sm_tests_cxx17 PRIVATE C2PA_SM_FIXTURE="${FIXTURE}")
c2pa_sm_target_flags(c2pa_sm_tests_cxx17)
add_test(NAME cxx17 COMMAND c2pa_sm_tests_cxx17)

add_executable(c2pa_sm_tests_cxx20 cpp/tests/tests_cxx20.cpp)
target_link_libraries(c2pa_sm_tests_cxx20 PRIVATE c2pa_sm_cpp)
target_include_directories(c2pa_sm_tests_cxx20 PRIVATE cpp/include)
set_target_properties(c2pa_sm_tests_cxx20 PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_compile_definitions(c2pa_sm_tests_cxx20 PRIVATE C2PA_SM_FIXTURE="${FIXTURE}")
c2pa_sm_target_flags(c2pa_sm_tests_cxx20)
add_test(NAME cxx20 COMMAND c2pa_sm_tests_cxx20)

add_executable(c2pa_sm_tests_pool cpp/tests/tests_pool.cpp)
target_link_libraries(c2pa_sm_tests_pool PRIVATE c2pa_sm_cpp)
set_target_properties(c2pa_sm_tests_pool PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
c2pa_sm_target_flags(c2pa_sm_tests_pool)
add_test(NAME pool COMMAND c2pa_sm_tests_pool)

add_subdirectory(examples)
