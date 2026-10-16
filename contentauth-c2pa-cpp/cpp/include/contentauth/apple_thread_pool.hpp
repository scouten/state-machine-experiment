// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#ifndef CONTENTAUTH_APPLE_THREAD_POOL_HPP
#define CONTENTAUTH_APPLE_THREAD_POOL_HPP

#if !defined(__APPLE__)
#error "apple_thread_pool.hpp is only available on Apple platforms"
#endif

#include <functional>
#include <memory>

#include "contentauth/thread_pool.hpp"

namespace c2pa::sm {

/// A private concurrent GCD queue. Waits for everything posted on destruction.
class AppleThreadPool final : public ThreadPool {
public:
    AppleThreadPool();
    ~AppleThreadPool() override;

    void post(std::function<void()> task) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_APPLE_THREAD_POOL_HPP
