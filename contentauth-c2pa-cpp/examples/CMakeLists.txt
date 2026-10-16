# The examples build the way a client of the library would: they see only the
# public `c2pa_sm_cpp` target, and so only `include/`. The signing example
# supplies its own OpenSSL-backed host callback, not a library key provider.

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

if(UNIX)
	add_executable(c2pa_sm_sign sign.cpp)
	target_link_libraries(c2pa_sm_sign PRIVATE c2pa_sm_cpp OpenSSL::Crypto)
	set_target_properties(c2pa_sm_sign PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
	c2pa_sm_target_flags(c2pa_sm_sign)
	add_test(NAME example_sign COMMAND c2pa_sm_sign "${FIXTURE}"
		"${CMAKE_BINARY_DIR}/example-signed.jpg" "${CMAKE_BINARY_DIR}/signing-definition.json"
		"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.der"
		"${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem" "1800000000")
	set_tests_properties(example_sign PROPERTIES
		PASS_REGULAR_EXPRESSION "\"validation_state\"[ \t\r\n]*:[ \t\r\n]*\"Trusted\"")
	add_test(NAME example_sign_usage COMMAND c2pa_sm_sign)
	set_tests_properties(example_sign_usage PROPERTIES WILL_FAIL TRUE)
	find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
	add_test(NAME example_sign_mismatched_key COMMAND "${CMAKE_COMMAND}"
		"-DOPENSSL=${OPENSSL_EXECUTABLE}" "-DSIGNER=$<TARGET_FILE:c2pa_sm_sign>"
		"-DSOURCE=${FIXTURE}" "-DBUILD_DIR=${CMAKE_BINARY_DIR}"
		"-DCERTIFICATE=${WORKSPACE_ROOT}/contentauth-c2pa-builder/tests/fixtures/test-signer.der"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/test_mismatched_key.cmake")
endif()
