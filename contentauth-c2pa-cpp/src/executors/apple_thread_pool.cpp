// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#include "apple_thread_pool.hpp"

#include <dispatch/dispatch.h>

#include <utility>

namespace c2pa::sm {

struct AppleThreadPool::Impl {
    dispatch_queue_t queue;
    dispatch_group_t group;
};

AppleThreadPool::AppleThreadPool() : impl_(std::make_unique<Impl>()) {
    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(
        DISPATCH_QUEUE_CONCURRENT, QOS_CLASS_USER_INITIATED, 0);
    impl_->queue = dispatch_queue_create("com.adobe.contentauth.c2pa-sm.pool", attr);
    impl_->group = dispatch_group_create();
}

AppleThreadPool::~AppleThreadPool() {
    dispatch_group_wait(impl_->group, DISPATCH_TIME_FOREVER);
    dispatch_release(impl_->group);
    dispatch_release(impl_->queue);
}

void AppleThreadPool::post(std::function<void()> task) {
    // The _f variant takes a plain function pointer, so no blocks extension is needed.
    auto *owned = new std::function<void()>(std::move(task));
    dispatch_group_async_f(impl_->group, impl_->queue, owned, [](void *context) {
        std::unique_ptr<std::function<void()>> task(static_cast<std::function<void()> *>(context));
        (*task)();
    });
}

std::unique_ptr<ThreadPool> make_apple_thread_pool() {
    return std::make_unique<AppleThreadPool>();
}

}  // namespace c2pa::sm
