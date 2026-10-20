// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#include "assertions.hpp"

using namespace c2pa::sm;

TEST(ExceptionAssertions, accepts_the_expected_code_and_executes_once) {
    int calls = 0;
    EXPECT_THROW_CODE((++calls, throw Exception(ErrorCode::Read, "Read", "read refused")),
                      ErrorCode::Read);
    EXPECT_EQ(calls, 1);
}

TEST(ExceptionAssertions, reports_a_missing_exception) {
    const auto result = support::throws_code([] {}, ErrorCode::Read);
    EXPECT_FALSE(result);
    EXPECT_NE(std::string(result.message()).find("nothing was thrown"), std::string::npos);
}

TEST(ExceptionAssertions, reports_the_wrong_error_code) {
    const auto result = support::throws_code([] {
        throw Exception(ErrorCode::InvalidArgument, "InvalidArgument", "bad input");
    }, ErrorCode::Read);
    EXPECT_FALSE(result);
    const std::string message = result.message();
    EXPECT_NE(message.find("Expected error code"), std::string::npos);
    EXPECT_NE(message.find("got "), std::string::npos);
    EXPECT_NE(message.find("bad input"), std::string::npos);
}

TEST(ExceptionAssertions, reports_standard_and_nonstandard_exception_types) {
    const auto standard = support::throws_code([] {
        throw std::runtime_error("different exception");
    }, ErrorCode::Read);
    EXPECT_FALSE(standard);
    EXPECT_NE(std::string(standard.message()).find("another std::exception: different exception"),
              std::string::npos);
    const auto nonstandard = support::throws_code([] { throw 42; }, ErrorCode::Read);
    EXPECT_FALSE(nonstandard);
    EXPECT_NE(std::string(nonstandard.message()).find("non-standard exception"), std::string::npos);
}
