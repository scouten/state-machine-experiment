#include "contentauth/c2pa_sm_sign_async.hpp"
#include "scope_exit.hpp"
#include "signing_support.hpp"

#include <memory>
#include <type_traits>

using namespace c2pa::sm;
using namespace support;

TEST(AsyncSigning, scope_exit_runs_once_after_normal_exit_and_early_return) {
    int calls = 0;
    auto cleanup = [&calls]() noexcept { ++calls; };
    {
        auto guard = detail::make_scope_exit(cleanup);
        static_assert(!std::is_copy_constructible_v<decltype(guard)>);
        static_assert(!std::is_copy_assignable_v<decltype(guard)>);
        static_assert(!std::is_move_constructible_v<decltype(guard)>);
        static_assert(!std::is_move_assignable_v<decltype(guard)>);
        static_assert(std::is_nothrow_destructible_v<decltype(guard)>);
        EXPECT_EQ(calls, 0);
    }
    EXPECT_EQ(calls, 1);
    const auto run = [&] {
        auto guard = detail::make_scope_exit(cleanup);
        return 42;
    };
    EXPECT_EQ(run(), 42);
    EXPECT_EQ(calls, 2);
}

TEST(AsyncSigning, scope_exit_runs_during_exception_unwinding) {
    int calls = 0;
    bool caught = false;
    try {
        auto guard = detail::make_scope_exit([&calls]() noexcept { ++calls; });
        throw std::runtime_error("scope-exit test");
    } catch (const std::runtime_error &) {
        caught = true;
        EXPECT_EQ(calls, 1);
    }
    EXPECT_TRUE(caught);
    EXPECT_EQ(calls, 1);
}

TEST(AsyncSigning, scope_exit_owns_move_only_callables_and_runs_in_reverse_scope_order) {
    int sequence = 0;
    {
        auto first = detail::make_scope_exit(
            [&sequence, value = std::make_unique<int>(1)]() noexcept {
                sequence = sequence * 10 + *value;
            });
        {
            auto second = detail::make_scope_exit([&sequence]() noexcept {
                sequence = sequence * 10 + 2;
            });
            EXPECT_EQ(sequence, 0);
        }
        EXPECT_EQ(sequence, 2);
    }
    EXPECT_EQ(sequence, 21);
}

TEST(AsyncSigning, pooled_build_fifo_uses_one_task_and_allows_reentrant_submission) {
    struct ManualPool : ThreadPool {
        std::vector<std::function<void()>> tasks;
        void post(std::function<void()> task) override { tasks.push_back(std::move(task)); }
    } pool;
    MemoryBuildHost backing({1, 2, 3});
    PooledBuildHost host(backing, pool);
    std::vector<int> order;
    host.start(BuildLengthRequest{1, BuildStream::Source}, [&](BuildReply reply) {
        EXPECT_EQ(std::get<Length>(reply).value, uint64_t{3});
        order.push_back(1);
        host.start(BuildLengthRequest{3, BuildStream::Source}, [&](BuildReply) { order.push_back(3); });
        throw std::runtime_error("callback must not stop the drain");
    });
    host.start(BuildLengthRequest{2, BuildStream::Source}, [&](BuildReply) { order.push_back(2); });
    EXPECT_EQ(pool.tasks.size(), size_t{1});
    pool.tasks.front()();
    EXPECT_TRUE(order == std::vector<int>({1, 2, 3}));
    host.start(BuildLengthRequest{4, BuildStream::Source}, [&](BuildReply) { order.push_back(4); });
    EXPECT_EQ(pool.tasks.size(), size_t{2});
    pool.tasks.back()();
    EXPECT_TRUE(order == std::vector<int>({1, 2, 3, 4}));
}

TEST(AsyncSigning, serialized_build_work_does_not_park_the_other_pool_worker) {
    struct Blocked : MemoryBuildHost {
        std::promise<void> entered;
        std::shared_future<void> release;
        explicit Blocked(std::shared_future<void> signal) : MemoryBuildHost({1}), release(std::move(signal)) {}
        uint64_t length(BuildStream stream) override {
            if (!started.exchange(true)) {
                entered.set_value();
                release.wait();
            }
            return MemoryBuildHost::length(stream);
        }
        std::atomic<bool> started{false};
    };
    std::promise<void> release;
    Blocked backing(release.get_future().share());
    auto pool = make_simple_thread_pool(2);
    PooledBuildHost host(backing, *pool);
    std::atomic<int> completed{0};
    host.start(BuildLengthRequest{1, BuildStream::Source}, [&](BuildReply) { ++completed; });
    backing.entered.get_future().get();
    for (uint64_t id = 2; id < 20; ++id)
        host.start(BuildLengthRequest{id, BuildStream::Source}, [&](BuildReply) { ++completed; });
    std::promise<void> unrelated;
    auto ready = unrelated.get_future();
    pool->post([&] { unrelated.set_value(); });
    const bool ran = ready.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    release.set_value();
    pool.reset();
    EXPECT_TRUE(ran);
    EXPECT_EQ(completed.load(), 19);
}

TEST(AsyncSigning, rejected_fifo_drain_completes_concurrent_submissions_and_can_retry) {
    struct RejectOnce : ThreadPool {
        std::promise<void> entered;
        std::shared_future<void> release;
        bool reject = true;
        std::vector<std::function<void()>> accepted;
        explicit RejectOnce(std::shared_future<void> signal) : release(std::move(signal)) {}
        void post(std::function<void()> task) override {
            if (reject) {
                entered.set_value();
                release.wait();
                reject = false;
                throw 42;
            }
            accepted.push_back(std::move(task));
        }
    };
    std::promise<void> release;
    RejectOnce pool(release.get_future().share());
    MemoryBuildHost backing({1});
    PooledBuildHost host(backing, pool);
    std::atomic<int> failures{0};
    auto done = [&](BuildReply reply) { if (std::holds_alternative<Failed>(reply)) ++failures; };
    std::thread first([&] {
        EXPECT_NO_THROW(host.start(BuildLengthRequest{1, BuildStream::Source}, [&](BuildReply reply) {
            done(std::move(reply));
            throw std::runtime_error("rejected callback must not strand the remaining requests");
        }));
    });
    pool.entered.get_future().get();
    host.start(BuildLengthRequest{2, BuildStream::Source}, done);
    release.set_value();
    first.join();
    EXPECT_EQ(failures.load(), 2);
    bool recovered = false;
    host.start(BuildLengthRequest{3, BuildStream::Source}, [&](BuildReply reply) {
        recovered = std::holds_alternative<Length>(reply);
    });
    EXPECT_EQ(pool.accepted.size(), size_t{1});
    pool.accepted.front()();
    EXPECT_TRUE(recovered);
}

TEST(AsyncSigning, build_wait_quiesces_a_callback_selected_before_terminal_error) {
    ManualBuildHost host;
    Building building(BuildSession(signing_settings()), host);
    EXPECT_TRUE(!building.step());
    std::promise<void> entered, release;
    auto released = release.get_future().share();
    EXPECT_TRUE(building.mailbox().set_waker([&] {
        entered.set_value();
        released.wait();
    }));
    std::thread delivery([&] { host.deliver(); });
    entered.get_future().get();
    building.mailbox().post(UINT64_MAX, Written{});
    EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
    auto waiter = std::async(std::launch::async, [&] { building.wait(); });
    const bool blocked = waiter.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout;
    release.set_value();
    delivery.join();
    waiter.get();
    EXPECT_TRUE(blocked);
    EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
}

TEST(AsyncSigning, parallel_and_future_builds_drain_a_failed_hash_window_before_releasing_the_host) {
    struct FailedWindow : AsyncBuildHost {
        MemoryBuildHost backing;
        std::shared_future<void> release;
        std::promise<void> accepted;
        std::vector<std::thread> workers;
        bool failed = false, signalled = false;
        int failure;

        static std::vector<uint8_t> large_asset() {
            auto bytes = fixture_bytes();
            bytes.resize(512 * 1024);
            return bytes;
        }
        FailedWindow(std::shared_future<void> signal, int mode)
            : backing(large_asset(), fixture_sign), release(std::move(signal)), failure(mode) {}
        ~FailedWindow() override { for (auto &worker : workers) worker.join(); }
        void start(BuildRequest request, BuildCompletion done) override {
            const auto *read = std::get_if<BuildReadRequest>(&request);
            if (!read || read->stream != BuildStream::Output) {
                done(answer(backing, request));
                return;
            }
            if (!failed) {
                failed = true;
                if (failure == 0) { done(Failed{"hash read failed"}); return; }
                if (failure == 1) throw std::runtime_error("hash read start failed");
                done(Written{});
                return;
            }
            workers.emplace_back([this, request = std::move(request), done = std::move(done)] {
                release.wait();
                auto reply = answer(backing, request);
                done(reply);
                done(std::move(reply));
            });
            if (!signalled) {
                signalled = true;
                accepted.set_value();
            }
        }
    };
    for (bool own_host : {false, true}) {
        for (int failure = 0; failure < 3; ++failure) {
            std::promise<void> release;
            auto host = std::make_shared<FailedWindow>(release.get_future().share(), failure);
            auto accepted = host->accepted.get_future();
            auto result = own_host
                ? build_future(BuildSession(signing_settings()), host)
                : std::async(std::launch::async, [&] {
                    return build_parallel(BuildSession(signing_settings()), *host);
                });
            const bool pending = accepted.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            std::weak_ptr<FailedWindow> retained = host;
            if (own_host) host.reset();
            const bool blocked = result.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout;
            const bool alive = !retained.expired();
            release.set_value();
            bool failed = false;
            try { (void)result.get(); }
            catch (const Exception &) { failed = true; }
            host.reset();
            EXPECT_TRUE(pending);
            EXPECT_TRUE(blocked);
            EXPECT_TRUE(alive);
            EXPECT_TRUE(failed);
            EXPECT_TRUE(retained.expired());
        }
    }
}
