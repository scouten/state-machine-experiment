// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The coroutine driver, which needs C++20.

#include <set>
#include <deque>
#include <cstdlib>
#include <exception>

#include "contentauth/c2pa_sm_coro.hpp"
#include "contentauth/c2pa_sm_sign.hpp"
#include "contentauth/c2pa_sm_sign_async.hpp"
#include "contentauth/c2pa_sm_sign_coro.hpp"
#include "support.hpp"
#include "signing_support.hpp"

#if defined(C2PA_SM_GCOV)
extern "C" void __gcov_dump();
#elif defined(C2PA_SM_LLVM_PROFILE)
extern "C" int __llvm_profile_write_file();
#endif

using namespace c2pa::sm;
using namespace support;

namespace {

std::string reference_json() {
    MemoryHost host = fixture_host();
    return json_of(read(Session("image/jpeg"), host));
}

Task<std::optional<Reader>> read_twice_and_return_second(AsyncHost &host) {
    auto first = co_await co_read(Session("image/jpeg"), host);
    EXPECT_TRUE(first.has_value());
    co_return co_await co_read(Session("image/jpeg"), host);
}

Task<int> throws_after_a_read(AsyncHost &host) {
    (void)co_await co_read(Session("image/jpeg"), host);
    throw std::runtime_error("from inside the coroutine");
    co_return 0;
}

Task<std::optional<Reader>> bad_format(AsyncHost &host) {
    co_return co_await co_read(Session("image/png"), host);
}

Task<int> immediate_value() { co_return 42; }

struct CaptureWaker {
    std::function<void()> &waker;
    bool await_ready() const noexcept { return false; }
    void await_suspend(Task<int>::Handle handle) {
        waker = detail::coroutine_waker(handle);
    }
    void await_resume() const noexcept {}
};

Task<int> capture_waker(std::function<void()> &waker, int &resumed) {
    co_await CaptureWaker{waker};
    ++resumed;
    co_return 42;
}

[[noreturn]] void expected_termination() {
    // Expected process death skips normal profile finalizers.
#if defined(C2PA_SM_GCOV)
    __gcov_dump();
#elif defined(C2PA_SM_LLVM_PROFILE)
    if (__llvm_profile_write_file() != 0) std::_Exit(87);
#endif
    std::_Exit(86);
}

}  // namespace

TEST(CoroutineDeathTest, throwing_spawn_completion_terminates) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT({
        std::set_terminate(expected_termination);
        spawn(immediate_value(), [](Outcome<int>) {
            throw std::runtime_error("spawn completion must not throw");
        });
    }, ::testing::ExitedWithCode(86), "");
}

TEST(Coroutines, task_move_assignment_preserves_results_and_accepts_self_move) {
    auto task = immediate_value();
    auto &alias = task;
    task = std::move(alias);
    EXPECT_EQ(std::move(task).get(), 42);
    auto replacement = immediate_value();
    task = std::move(replacement);
    EXPECT_EQ(std::move(task).get(), 42);
}

TEST(Coroutines, saved_wakers_do_not_resume_destroyed_tasks) {
    for (bool complete_first : {false, true}) {
        std::function<void()> waker;
        int resumed = 0;
        {
            auto task = capture_waker(waker, resumed);
            task.await_suspend(std::noop_coroutine()).resume();
            ASSERT_TRUE(waker);
            EXPECT_EQ(resumed, 0);
            if (complete_first) {
                waker();
                EXPECT_EQ(task.await_resume(), 42);
            }
        }
        waker();
        EXPECT_EQ(resumed, complete_first ? 1 : 0);
    }
}

TEST(Coroutines, a_coroutine_reads_with_a_pool_and_resumes_on_a_pool_thread) {
    SlowHost slow(std::chrono::milliseconds(5));
    SimpleThreadPool pool(8);
    PooledHost host(slow, pool);

    auto reader = co_read(Session("image/jpeg"), host).get();
    EXPECT_EQ(json_of(reader), reference_json());
    EXPECT_TRUE(slow.max_in_flight() > 1);
}

TEST(Coroutines, get_may_free_the_frame_the_instant_the_task_completes_on_another_thread) {
    // The task finishes on a pool thread while the caller is parked in
    // get(); the caller then destroys the frame immediately. Many quick
    // rounds, so a completer that touched the frame after signalling would
    // be caught by ASan/TSan.
    MemoryHost backing = fixture_host();
    SimpleThreadPool pool(4);
    PooledHost host(backing, pool);
    const std::string expected = reference_json();
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(json_of(co_read(Session("image/jpeg"), host).get()), expected);
    }
}

TEST(Coroutines, coroutines_compose_and_propagate_exceptions) {
    MemoryHost backing = fixture_host();
    SimpleThreadPool pool(4);
    PooledHost host(backing, pool);

    EXPECT_EQ(json_of(read_twice_and_return_second(host).get()), reference_json());
    EXPECT_THROW_CODE(bad_format(host).get(), ErrorCode::UnsupportedType);

    bool threw = false;
    try {
        throws_after_a_read(host).get();
    } catch (const std::runtime_error &e) {
        threw = std::string(e.what()) == "from inside the coroutine";
    }
    EXPECT_TRUE(threw);
}

TEST(Coroutines, a_host_that_completes_inline_never_suspends_the_coroutine) {
    // `done` is called from inside `start`, so a reply is always already
    // waiting when the coroutine goes to wait for one.
    struct Inline : AsyncHost {
        MemoryHost backing = fixture_host();
        void start(const Request &request, Completion done) override {
            done(answer(backing, request));
        }
    } host;
    EXPECT_EQ(json_of(co_read(Session("image/jpeg"), host).get()), reference_json());
}

TEST(Coroutines, the_session_migrates_between_threads_but_never_runs_on_two_at_once) {
    // Resumption happens on whichever thread posts the reply; record which.
    struct Recording : AsyncHost {
        MemoryHost backing = fixture_host();
        SimpleThreadPool pool{4};
        std::mutex m;
        std::set<std::thread::id> completers;
        void start(const Request &request, Completion done) override {
            pool.post([this, request, done = std::move(done)] {
                {
                    std::lock_guard<std::mutex> lock(m);
                    completers.insert(std::this_thread::get_id());
                }
                done(answer(backing, request));
            });
        }
    } host;

    std::vector<Task<std::optional<Reader>>> tasks;
    for (int i = 0; i < 8; ++i) {
        tasks.push_back(co_read(Session("image/jpeg"), host));
    }
    for (auto &task : tasks) {
        EXPECT_EQ(json_of(std::move(task).get()), reference_json());
    }
    EXPECT_TRUE(!host.completers.empty());
}

TEST(Coroutines, many_reads_are_spawned_from_one_thread_and_share_a_few_io_threads) {
    SlowHost slow(std::chrono::milliseconds(2));
    SimpleThreadPool pool(8);
    PooledHost host(slow, pool);
    const std::string expected = reference_json();

    constexpr int kReads = 24;
    std::mutex m;
    std::condition_variable cv;
    int finished = 0, matching = 0, failed = 0;
    for (int i = 0; i < kReads; ++i) {
        // Format "image/png" is rejected while *constructing* the session,
        // so the one failing read is made inside a coroutine instead.
        Task<std::optional<Reader>> task = i == 0 ? bad_format(host)
                                                  : co_read(Session("image/jpeg"), host);
        spawn(std::move(task), [&](Outcome<std::optional<Reader>> outcome) {
            std::lock_guard<std::mutex> lock(m);
            if (outcome.index() == 1) {
                ++failed;
            } else if (json_of(std::get<0>(outcome)) == expected) {
                ++matching;
            }
            ++finished;
            cv.notify_all();
        });
    }
    {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [&] { return finished == kReads; });
    }
    EXPECT_EQ(matching, kReads - 1);
    EXPECT_EQ(failed, 1);
    // Far more reads were under way than the pool has threads, and the host
    // was kept busy by all of them at once.
    EXPECT_TRUE(slow.max_in_flight() > 3);
}

namespace {

/// An eagerly started, caller-owned coroutine: the smallest thing that can
/// start a `co_read` without blocking, and then destroy it mid-suspension.
struct Fire {
    struct promise_type {
        Fire get_return_object() {
            return Fire{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() { std::terminate(); }
    };
    explicit Fire(std::coroutine_handle<promise_type> h) : handle(h) {}
    Fire(Fire &&other) noexcept : handle(std::exchange(other.handle, {})) {}
    ~Fire() {
        if (handle) {
            handle.destroy();
        }
    }
    std::coroutine_handle<promise_type> handle;
};

Fire run(AsyncHost &host, std::optional<std::string> &json, bool &done) {
    json = json_of(co_await co_read(Session("image/jpeg"), host));
    done = true;
}

}  // namespace

TEST(Coroutines, a_single_thread_can_drive_a_coroutine_by_completing_its_requests) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    std::optional<std::string> json;
    bool done = false;
    Fire fire = run(host, json, done);

    // The coroutine ran to its first suspension and parked requests.
    EXPECT_TRUE(!done);
    EXPECT_TRUE(host.parked() > 0);
    // Completing a request posts its reply, which resumes the coroutine
    // right here on this thread — no thread, no loop, no scheduler.
    while (host.parked() > 0) {
        host.complete(0);
    }
    EXPECT_TRUE(done);
    EXPECT_TRUE(json.has_value() && *json == reference_json());
}

TEST(Coroutines, destroying_a_suspended_coroutine_cancels_the_read) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    std::optional<std::string> json;
    bool done = false;
    {
        Fire fire = run(host, json, done);
        EXPECT_TRUE(host.parked() > 0);
    }  // the coroutine, suspended mid-read, is destroyed here

    // The host's requests were already started. They complete now, after
    // the session is gone, and must find nothing to resume or corrupt
    // (ASan and TSan hold this to account in CI).
    while (host.parked() > 0) {
        host.complete(0);
    }
    EXPECT_TRUE(!done);
}

namespace {

class InlineBuildHost : public AsyncBuildHost {
public:
    MemoryBuildHost backing;

    explicit InlineBuildHost(BuildTimestamp timestamp = {})
        : backing(fixture_bytes(), fixture_sign, std::move(timestamp)) {}

    void start(BuildRequest request, BuildCompletion done) override {
        auto reply = answer(backing, request);
        done(std::move(reply));
        done(std::move(reply));
    }
};

Task<SignReport> chained_build(AsyncBuildHost &host, std::thread::id &resumed) {
    auto report = co_await co_build_and_sign(BuildSession(signing_settings()), host);
    resumed = std::this_thread::get_id();
    co_return report;
}

Task<SignReport> throwing_build_chain(AsyncBuildHost &host) {
    (void)co_await co_build_and_sign(BuildSession(signing_settings()), host);
    throw std::runtime_error("after signing");
    co_return SignReport{};
}

}

TEST(Coroutines, coroutine_signing_inline_get_returns_owned_trusted_report) {
    SignReport owned;
    {
        InlineBuildHost host;
        owned = co_build_and_sign(BuildSession(signing_settings()), host).get();
        const auto json = trusted_signing_json(host.backing.output());
        EXPECT_TRUE(json.find("Trusted") != std::string::npos);
        EXPECT_TRUE(json.find("c2pa.actions.v2") != std::string::npos);
        EXPECT_TRUE(json.find("baseline.jpg") != std::string::npos);
    }
    EXPECT_TRUE(!owned.manifest.empty());
    EXPECT_TRUE(!owned.exclusions.empty());
}

TEST(Coroutines, coroutine_signing_queued_builds_interleave_without_redispatch) {
    ManualBuildHost first, second;
    int completed = 0;
    auto done = [&](Outcome<SignReport> result) {
        EXPECT_TRUE(std::holds_alternative<SignReport>(result));
        EXPECT_TRUE(!std::get<SignReport>(result).manifest.empty());
        ++completed;
    };
    spawn(co_build_and_sign(BuildSession(signing_settings()), first), done);
    spawn(co_build_and_sign(BuildSession(signing_settings()), second), done);
    EXPECT_EQ(completed, 0);
    EXPECT_EQ(first.pending.size(), second.pending.size());
    const auto stalled = first.pending.size();
    EXPECT_TRUE(stalled > 0);
    second.deliver();
    EXPECT_EQ(first.pending.size(), stalled);
    for (size_t round = 0; completed != 2 && round < 1000; ++round) {
        if (!first.pending.empty()) first.deliver();
        if (!second.pending.empty()) second.deliver();
    }
    EXPECT_EQ(completed, 2);
    EXPECT_TRUE(trusted_signing_json(first.backing.output()).find("Trusted") != std::string::npos);
    EXPECT_TRUE(trusted_signing_json(second.backing.output()).find("Trusted") != std::string::npos);
}

TEST(Coroutines, coroutine_signing_cancellation_keeps_owned_requests_and_late_callbacks_safe) {
    ManualBuildHost host;
    {
        auto task = co_build_and_sign(BuildSession(signing_settings()), host);
        task.await_suspend(std::noop_coroutine()).resume();
        for (size_t round = 0; round < 1000; ++round) {
            EXPECT_TRUE(!host.pending.empty());
            if (std::holds_alternative<WriteRequest>(host.pending.front().first)) break;
            host.deliver();
        }
        EXPECT_TRUE(std::holds_alternative<WriteRequest>(host.pending.front().first));
    }
    const auto &write = std::get<WriteRequest>(host.pending.front().first);
    EXPECT_TRUE(!write.bytes.empty());
    host.deliver();
    EXPECT_TRUE(host.pending.empty());
}

TEST(Coroutines, coroutine_signing_pool_resumes_await_chain_on_delivery_thread) {
    std::promise<void> release;
    auto ready = release.get_future().share();
    MemoryBuildHost backing(fixture_bytes(), [ready](const auto &algorithm, const auto &data) {
        ready.wait();
        return fixture_sign(algorithm, data);
    });
    SimpleThreadPool pool(2);
    PooledBuildHost host(backing, pool);
    std::thread::id resumed;
    std::promise<Outcome<SignReport>> completed;
    auto result = completed.get_future();
    spawn(chained_build(host, resumed), [&](Outcome<SignReport> outcome) {
        completed.set_value(std::move(outcome));
    });
    release.set_value();
    auto report = std::get<SignReport>(result.get());
    EXPECT_TRUE(resumed != std::this_thread::get_id());
    EXPECT_TRUE(!report.manifest.empty());
    EXPECT_TRUE(trusted_signing_json(backing.output()).find("Trusted") != std::string::npos);
}

TEST(Coroutines, coroutine_signing_get_can_free_frames_immediately_after_cross_thread_completion) {
    auto pool = make_simple_thread_pool(4);
    for (size_t iteration = 0; iteration < 32; ++iteration) {
        auto backing = std::make_shared<MemoryBuildHost>(fixture_bytes(), fixture_sign);
        PooledBuildHost host(backing, *pool);
        const auto report = co_build_and_sign(BuildSession(signing_settings()), host).get();
        EXPECT_TRUE(!report.manifest.empty());
        EXPECT_TRUE(!report.exclusions.empty());
        if (iteration == 31) {
            EXPECT_TRUE(trusted_signing_json(backing->output()).find("Trusted") != std::string::npos);
        }
    }
    pool.reset();
}

TEST(Coroutines, coroutine_signing_await_chain_captures_user_exceptions) {
    InlineBuildHost host;
    bool caught = false;
    try { (void)throwing_build_chain(host).get(); }
    catch (const std::runtime_error &error) { caught = std::string(error.what()) == "after signing"; }
    EXPECT_TRUE(caught);
}

TEST(Coroutines, coroutine_signing_spawn_propagates_start_throws_and_bad_replies) {
    struct Broken : AsyncBuildHost {
        int mode = 0;

        void start(BuildRequest, BuildCompletion done) override {
            if (mode == 0) throw std::runtime_error("start refused");
            if (mode == 1) throw 42;
            if (mode == 2) done(Written{});
            else done(Failed{"host refused"});
        }
    } host;
    for (int mode = 0; mode < 4; ++mode) {
        host.mode = mode;
        bool completed = false;
        spawn(co_build_and_sign(BuildSession(signing_settings()), host), [&](Outcome<SignReport> result) {
            EXPECT_TRUE(std::holds_alternative<std::exception_ptr>(result));
            bool caught = false;
            try { std::rethrow_exception(std::get<std::exception_ptr>(result)); }
            catch (const Exception &) { caught = true; }
            EXPECT_TRUE(caught);
            completed = true;
        });
        EXPECT_TRUE(completed);
    }
    EXPECT_THROW_CODE(co_build_and_sign(BuildSession(signing_settings()), host).get(),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
}

TEST(Coroutines, coroutine_signing_timestamp_transport_fails_closed) {
    const std::vector<BuildTimestamp> callbacks{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("offline"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1, 2}; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{0x30, 5, 0x30, 3, 2, 1, 2}; },
    };
    for (const auto &callback : callbacks) {
        InlineBuildHost host(callback);
        EXPECT_THROW_CODE(co_build_and_sign(BuildSession(signing_settings(true)), host).get(),
                          static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
    bool called = false;
    InlineBuildHost synthetic_tsa([&](const auto &url, const auto &body) {
        EXPECT_EQ(url, "https://tsa.example/");
        EXPECT_TRUE(!body.empty() && body.front() == 0x30);
        called = true;
        return std::vector<uint8_t>{0x30, 8, 0x30, 3, 2, 1, 0, 0x30, 1, 0};
    });
    const auto report = co_build_and_sign(BuildSession(signing_settings(true)), synthetic_tsa).get();
    EXPECT_TRUE(called);
    EXPECT_TRUE(!report.manifest.empty());
}

namespace {

class ThreadedBuildHost : public AsyncBuildHost {
public:
    std::promise<void> first_delivery;
    ThreadedBuildHost() : worker_([this] { run(); }) {}
    ~ThreadedBuildHost() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        ready_.notify_one();
        worker_.join();
    }
    void start(BuildRequest request, BuildCompletion done) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            requests_.emplace_back(std::move(request), std::move(done));
        }
        ready_.notify_one();
    }
private:
    void run() {
        bool first = true;
        for (;;) {
            std::pair<BuildRequest, BuildCompletion> request;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                ready_.wait(lock, [&] { return stopping_ || !requests_.empty(); });
                if (requests_.empty()) return;
                request = std::move(requests_.front());
                requests_.pop_front();
            }
            auto reply = answer(backing_, request.first);
            if (first) {
                first = false;
                first_delivery.set_value();
            }
            request.second(std::move(reply));
            request.second(std::move(reply));
        }
    }
    MemoryBuildHost backing_{fixture_bytes(), fixture_sign};
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::pair<BuildRequest, BuildCompletion>> requests_;
    bool stopping_ = false;
    std::thread worker_;
};

Task<SignReport> nested_cancel_build(AsyncBuildHost &host) {
    co_return co_await co_build_and_sign(BuildSession(signing_settings()), host);
}

Task<SignReport> pause_after_build(AsyncBuildHost &host, std::promise<void> &entered,
                                 std::shared_future<void> release) {
    auto result = co_await nested_cancel_build(host);
    entered.set_value();
    release.wait();
    co_return result;
}

}

TEST(Coroutines, task_destruction_races_real_host_delivery_and_nested_symmetric_transfer) {
    for (int iteration = 0; iteration < 200; ++iteration) {
        ThreadedBuildHost host;
        {
            auto task = nested_cancel_build(host);
            task.await_suspend(std::noop_coroutine()).resume();
            host.first_delivery.get_future().get();
            if (iteration % 2) std::this_thread::yield();
        }
    }
}

TEST(Coroutines, task_destruction_waits_for_a_resume_executing_in_an_awaiting_frame) {
    ThreadedBuildHost host;
    std::promise<void> entered, release;
    auto task = pause_after_build(host, entered, release.get_future().share());
    task.await_suspend(std::noop_coroutine()).resume();
    entered.get_future().get();
    std::promise<void> destroying;
    auto destroyed = std::async(std::launch::async, [task = std::move(task), &destroying, &host]() mutable {
        destroying.set_value();
        // Destroy via move assignment while the host is executing the parent
        // frame, not merely the mailbox awaiter in its nested child.
        auto replacement = nested_cancel_build(host);
        task = std::move(replacement);
    });
    destroying.get_future().get();
    const bool waited = destroyed.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout;
    release.set_value();
    destroyed.get();
    EXPECT_TRUE(waited);
}

TEST(Coroutines, read_task_destruction_uses_the_same_cross_thread_lifetime_gate) {
    auto pool = make_simple_thread_pool(4);
    MemoryHost backing = fixture_host();
    PooledHost host(backing, *pool);
    for (int iteration = 0; iteration < 200; ++iteration) {
        auto task = co_read(Session("image/jpeg"), host);
        task.await_suspend(std::noop_coroutine()).resume();
        std::this_thread::yield();
    }
    pool.reset();
}
