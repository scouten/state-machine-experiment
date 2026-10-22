// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#include "simple_thread_pool.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace c2pa::sm {

struct SimpleThreadPool::Impl {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::function<void()>> tasks;
    std::vector<std::thread> workers;
    bool stopping = false;

    void run() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [this] { return stopping || !tasks.empty(); });
                if (tasks.empty()) {
                    return;  // stopping, and drained
                }
                task = std::move(tasks.front());
                tasks.pop_front();
            }
            task();
        }
    }
};

SimpleThreadPool::SimpleThreadPool(size_t threads) : impl_(std::make_unique<Impl>()) {
    for (size_t i = 0; i < std::max<size_t>(threads, 1); ++i) {
        impl_->workers.emplace_back([impl = impl_.get()] { impl->run(); });
    }
}

SimpleThreadPool::~SimpleThreadPool() {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->stopping = true;
    }
    impl_->cv.notify_all();
    for (auto &worker : impl_->workers) {
        worker.join();
    }
}

void SimpleThreadPool::post(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->tasks.push_back(std::move(task));
    }
    impl_->cv.notify_one();
}

std::unique_ptr<ThreadPool> make_simple_thread_pool(size_t threads) {
    return std::make_unique<SimpleThreadPool>(threads);
}

}  // namespace c2pa::sm
