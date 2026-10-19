set(KEY "${BUILD_DIR}/example-mismatched.key.pem")
set(OUTPUT "${BUILD_DIR}/example-mismatched.jpg")
execute_process(
  COMMAND "${OPENSSL}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${KEY}"
  RESULT_VARIABLE KEY_RESULT ERROR_VARIABLE KEY_ERROR)
if(NOT KEY_RESULT STREQUAL "0")
  file(REMOVE "${KEY}")
  message(FATAL_ERROR "Cannot generate mismatched key: ${KEY_ERROR}")
endif()

execute_process(
  COMMAND "${SIGNER}" "${SOURCE}" "${OUTPUT}" "${BUILD_DIR}/signing-definition.json"
          "${CERTIFICATE}" "${KEY}" "1800000000"
  RESULT_VARIABLE RESULT OUTPUT_VARIABLE REPORT ERROR_VARIABLE ERROR)
file(REMOVE "${KEY}" "${OUTPUT}")
if(NOT RESULT STREQUAL "2")
  message(FATAL_ERROR "Mismatched key must exit 2, got ${RESULT}: ${REPORT} ${ERROR}")
endif()
if(NOT REPORT MATCHES "\"validation_state\"[ \t\r\n]*:[ \t\r\n]*\"Invalid\"")
  message(FATAL_ERROR "Expected an Invalid read-back report: ${REPORT} ${ERROR}")
endif()
if(NOT REPORT MATCHES "claimSignature.mismatch")
  message(FATAL_ERROR "Expected a signature mismatch: ${REPORT} ${ERROR}")
endif()
if(NOT ERROR MATCHES "signed output did not validate as Trusted")
  message(FATAL_ERROR "Expected verification failure diagnostic: ${ERROR}")
endif()
