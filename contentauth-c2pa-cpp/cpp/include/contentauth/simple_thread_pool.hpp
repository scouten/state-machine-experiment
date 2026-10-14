// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#ifndef CONTENTAUTH_SIMPLE_THREAD_POOL_HPP
#define CONTENTAUTH_SIMPLE_THREAD_POOL_HPP

#include <cstddef>
#include <functional>
#include <memory>

#include "contentauth/thread_pool.hpp"

namespace c2pa::sm {

/// Fixed worker count, one mutex-guarded FIFO queue. Joins on destruction
/// after running everything queued.
class SimpleThreadPool final : public ThreadPool {
public:
    explicit SimpleThreadPool(size_t threads);
    ~SimpleThreadPool() override;

    void post(std::function<void()> task) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_SIMPLE_THREAD_POOL_HPP
