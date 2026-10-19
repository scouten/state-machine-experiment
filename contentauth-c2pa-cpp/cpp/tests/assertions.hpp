// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#ifndef C2PA_SM_TEST_ASSERTIONS_HPP
#define C2PA_SM_TEST_ASSERTIONS_HPP

#include <gtest/gtest.h>

#include <exception>
#include <functional>

#include "contentauth/c2pa_sm.hpp"

namespace support {

inline testing::AssertionResult throws_code(const std::function<void()> &action,
                                           c2pa::sm::ErrorCode expected) {
    try {
        action();
    } catch (const c2pa::sm::Exception &error) {
        if (error.code() == expected) return testing::AssertionSuccess();
        return testing::AssertionFailure()
            << "Expected error code " << static_cast<int>(expected)
            << ", got " << static_cast<int>(error.code()) << ": " << error.what();
    } catch (const std::exception &error) {
        return testing::AssertionFailure()
            << "Expected c2pa::sm::Exception, got another std::exception: " << error.what();
    } catch (...) {
        return testing::AssertionFailure()
            << "Expected c2pa::sm::Exception, got a non-standard exception";
    }
    return testing::AssertionFailure() << "Expected c2pa::sm::Exception, but nothing was thrown";
}

}  // namespace support

#define EXPECT_THROW_CODE(expression, expected)                                      \
    EXPECT_TRUE(::support::throws_code([&] { (void)(expression); }, (expected)))       \
        << "Expression: " #expression

#endif
