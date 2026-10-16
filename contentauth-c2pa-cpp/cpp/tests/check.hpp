// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.
//
// A deliberately tiny test harness, so the binding's tests need no network
// access or third-party dependency to build.

#ifndef C2PA_SM_CHECK_HPP
#define C2PA_SM_CHECK_HPP

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace check {

struct Registry {
    std::vector<std::pair<std::string, std::function<void()>>> tests;
    int failures = 0;
    static Registry &get() {
        static Registry r;
        return r;
    }
};

struct Registrar {
    Registrar(const char *name, std::function<void()> fn) {
        Registry::get().tests.emplace_back(name, std::move(fn));
    }
};

inline int run_all() {
    auto &r = Registry::get();
    for (auto &[name, fn] : r.tests) {
        int before = r.failures;
        try {
            fn();
        } catch (const std::exception &e) {
            std::fprintf(stderr, "  uncaught exception: %s\n", e.what());
            ++r.failures;
        }
        std::printf("%s %s\n", r.failures == before ? "ok  " : "FAIL", name.c_str());
    }
    std::printf("%zu tests, %d failures\n", r.tests.size(), r.failures);
    return r.failures == 0 ? 0 : 1;
}

}  // namespace check

#define TEST(name)                                                      \
    static void test_##name();                                          \
    static check::Registrar registrar_##name(#name, test_##name);       \
    static void test_##name()

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            ++check::Registry::get().failures;                                           \
        }                                                                                \
    } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))

/// Passes if `expr` throws c2pa::sm::Exception with the given code.
#define CHECK_THROWS_CODE(expr, error_code)                                  \
    do {                                                                     \
        bool threw_ = false;                                                 \
        try {                                                                \
            (void)(expr);                                                    \
        } catch (const c2pa::sm::Exception &e_) {                            \
            threw_ = e_.code() == (error_code);                              \
        }                                                                    \
        CHECK(threw_);                                                       \
    } while (0)

#endif
