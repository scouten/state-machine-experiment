// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// What every ThreadPool must do, run against each pool the library ships.

#include <atomic>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

#include "check.hpp"
#include "contentauth/thread_pool.hpp"

using namespace c2pa::sm;

namespace {

using Factory = std::function<std::unique_ptr<ThreadPool>()>;

std::vector<Factory> pools() {
    std::vector<Factory> all;
    all.push_back([] { return make_simple_thread_pool(4); });
#if defined(__APPLE__)
    all.push_back([] { return make_apple_thread_pool(); });
#endif
    return all;
}

}  // namespace

TEST(every_posted_task_runs_exactly_once_and_destruction_waits_for_them) {
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 500;
    for (const Factory &make : pools()) {
        std::vector<std::atomic<int>> runs(kProducers * kPerProducer);
        {
            auto pool = make();
            std::vector<std::thread> producers;
            for (int p = 0; p < kProducers; ++p) {
                producers.emplace_back([&, p] {
                    for (int i = 0; i < kPerProducer; ++i) {
                        const int slot = p * kPerProducer + i;
                        pool->post([&runs, slot] { ++runs[slot]; });
                    }
                });
            }
            for (auto &producer : producers) {
                producer.join();
            }
        }  // the pool is destroyed with work possibly still queued
        for (auto &count : runs) {
            CHECK_EQ(count.load(), 1);
        }
    }
}

TEST(a_running_task_may_post_another) {
    for (const Factory &make : pools()) {
        std::atomic<int> ran{0};
        {
            auto pool = make();
            ThreadPool &ref = *pool;
            ref.post([&ref, &ran] {
                ++ran;
                ref.post([&ran] { ++ran; });
            });
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (ran < 2 && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        CHECK_EQ(ran.load(), 2);
    }
}

TEST(the_simple_pool_runs_as_many_tasks_at_once_as_it_has_workers) {
    // Each task waits for the other, so this only finishes with two workers.
    std::atomic<int> arrived{0};
    std::atomic<int> saw_both{0};
    {
        auto pool = make_simple_thread_pool(2);
        for (int i = 0; i < 2; ++i) {
            pool->post([&] {
                ++arrived;
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                while (arrived < 2 && std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::yield();
                }
                if (arrived == 2) {
                    ++saw_both;
                }
            });
        }
    }
    CHECK_EQ(saw_both.load(), 2);
}

TEST(the_simple_pool_always_has_at_least_one_worker) {
    std::atomic<int> ran{0};
    {
        auto pool = make_simple_thread_pool(0);
        pool->post([&] { ++ran; });
    }
    CHECK_EQ(ran.load(), 1);
}

int main() { return check::run_all(); }
