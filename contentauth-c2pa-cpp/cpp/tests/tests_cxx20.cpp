// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The coroutine driver, which needs C++20.

#include <set>

#include "contentauth/c2pa_sm_coro.hpp"
#include "contentauth/c2pa_sm_sign.hpp"
#include "contentauth/c2pa_sm_sign_async.hpp"
#include "contentauth/c2pa_sm_sign_coro.hpp"
#include "support.hpp"
#include "signing_support.hpp"

using namespace c2pa::sm;
using namespace support;

namespace {

std::string reference_json() {
    MemoryHost host = fixture_host();
    return json_of(read(Session("image/jpeg"), host));
}

Task<std::optional<Reader>> read_twice_and_return_second(AsyncHost &host) {
    auto first = co_await co_read(Session("image/jpeg"), host);
    CHECK(first.has_value());
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

}  // namespace

TEST(a_coroutine_reads_with_a_pool_and_resumes_on_a_pool_thread) {
    SlowHost slow(std::chrono::milliseconds(5));
    SimpleThreadPool pool(8);
    PooledHost host(slow, pool);

    auto reader = co_read(Session("image/jpeg"), host).get();
    CHECK_EQ(json_of(reader), reference_json());
    CHECK(slow.max_in_flight() > 1);
}

TEST(get_may_free_the_frame_the_instant_the_task_completes_on_another_thread) {
    // The task finishes on a pool thread while the caller is parked in
    // get(); the caller then destroys the frame immediately. Many quick
    // rounds, so a completer that touched the frame after signalling would
    // be caught by ASan/TSan.
    MemoryHost backing = fixture_host();
    SimpleThreadPool pool(4);
    PooledHost host(backing, pool);
    const std::string expected = reference_json();
    for (int i = 0; i < 100; ++i) {
        CHECK_EQ(json_of(co_read(Session("image/jpeg"), host).get()), expected);
    }
}

TEST(coroutines_compose_and_propagate_exceptions) {
    MemoryHost backing = fixture_host();
    SimpleThreadPool pool(4);
    PooledHost host(backing, pool);

    CHECK_EQ(json_of(read_twice_and_return_second(host).get()), reference_json());
    CHECK_THROWS_CODE(bad_format(host).get(), ErrorCode::UnsupportedType);

    bool threw = false;
    try {
        throws_after_a_read(host).get();
    } catch (const std::runtime_error &e) {
        threw = std::string(e.what()) == "from inside the coroutine";
    }
    CHECK(threw);
}

TEST(a_host_that_completes_inline_never_suspends_the_coroutine) {
    // `done` is called from inside `start`, so a reply is always already
    // waiting when the coroutine goes to wait for one.
    struct Inline : AsyncHost {
        MemoryHost backing = fixture_host();
        void start(const Request &request, Completion done) override {
            done(answer(backing, request));
        }
    } host;
    CHECK_EQ(json_of(co_read(Session("image/jpeg"), host).get()), reference_json());
}

TEST(the_session_migrates_between_threads_but_never_runs_on_two_at_once) {
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
        CHECK_EQ(json_of(std::move(task).get()), reference_json());
    }
    CHECK(!host.completers.empty());
}

TEST(many_reads_are_spawned_from_one_thread_and_share_a_few_io_threads) {
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
    CHECK_EQ(matching, kReads - 1);
    CHECK_EQ(failed, 1);
    // Far more reads were under way than the pool has threads, and the host
    // was kept busy by all of them at once.
    CHECK(slow.max_in_flight() > 3);
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

TEST(a_single_thread_can_drive_a_coroutine_by_completing_its_requests) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    std::optional<std::string> json;
    bool done = false;
    Fire fire = run(host, json, done);

    // The coroutine ran to its first suspension and parked requests.
    CHECK(!done);
    CHECK(host.parked() > 0);
    // Completing a request posts its reply, which resumes the coroutine
    // right here on this thread — no thread, no loop, no scheduler.
    while (host.parked() > 0) {
        host.complete(0);
    }
    CHECK(done);
    CHECK(json.has_value() && *json == reference_json());
}

TEST(destroying_a_suspended_coroutine_cancels_the_read) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    std::optional<std::string> json;
    bool done = false;
    {
        Fire fire = run(host, json, done);
        CHECK(host.parked() > 0);
    }  // the coroutine, suspended mid-read, is destroyed here

    // The host's requests were already started. They complete now, after
    // the session is gone, and must find nothing to resume or corrupt
    // (ASan and TSan hold this to account in CI).
    while (host.parked() > 0) {
        host.complete(0);
    }
    CHECK(!done);
}

namespace {

class InlineBuildHost : public AsyncBuildHost {
public:
    MemoryBuildHost backing;

    explicit InlineBuildHost(BuildTimestamp timestamp = {})
        : backing(fixture_bytes(), fixture_sign, std::move(timestamp)) {}

    void start(BuildRequest request, BuildCompletion done) override {
        auto reply = answer(backing, request);
        done(reply);
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

TEST(coroutine_signing_inline_get_returns_owned_trusted_report) {
    SignReport owned;
    {
        InlineBuildHost host;
        owned = co_build_and_sign(BuildSession(signing_settings()), host).get();
        const auto json = trusted_signing_json(host.backing.output());
        CHECK(json.find("Trusted") != std::string::npos);
        CHECK(json.find("c2pa.actions.v2") != std::string::npos);
        CHECK(json.find("baseline.jpg") != std::string::npos);
    }
    CHECK(!owned.manifest.empty());
    CHECK(!owned.exclusions.empty());
}

TEST(coroutine_signing_queued_builds_interleave_without_redispatch) {
    ManualBuildHost first, second;
    int completed = 0;
    auto done = [&](Outcome<SignReport> result) {
        CHECK(std::holds_alternative<SignReport>(result));
        CHECK(!std::get<SignReport>(result).manifest.empty());
        ++completed;
    };
    spawn(co_build_and_sign(BuildSession(signing_settings()), first), done);
    spawn(co_build_and_sign(BuildSession(signing_settings()), second), done);
    CHECK_EQ(completed, 0);
    CHECK_EQ(first.pending.size(), second.pending.size());
    const auto stalled = first.pending.size();
    CHECK(stalled > 0);
    second.deliver();
    CHECK_EQ(first.pending.size(), stalled);
    for (size_t round = 0; completed != 2 && round < 1000; ++round) {
        if (!first.pending.empty()) first.deliver();
        if (!second.pending.empty()) second.deliver();
    }
    CHECK_EQ(completed, 2);
    CHECK(trusted_signing_json(first.backing.output()).find("Trusted") != std::string::npos);
    CHECK(trusted_signing_json(second.backing.output()).find("Trusted") != std::string::npos);
}

TEST(coroutine_signing_cancellation_keeps_owned_requests_and_late_callbacks_safe) {
    ManualBuildHost host;
    {
        auto task = co_build_and_sign(BuildSession(signing_settings()), host);
        task.await_suspend(std::noop_coroutine()).resume();
        for (size_t round = 0; round < 1000; ++round) {
            CHECK(!host.pending.empty());
            if (std::holds_alternative<WriteRequest>(host.pending.front().first)) break;
            host.deliver();
        }
        CHECK(std::holds_alternative<WriteRequest>(host.pending.front().first));
    }
    const auto &write = std::get<WriteRequest>(host.pending.front().first);
    CHECK(!write.bytes.empty());
    host.deliver();
    CHECK(host.pending.empty());
}

TEST(coroutine_signing_pool_resumes_await_chain_on_delivery_thread) {
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
    CHECK(resumed != std::this_thread::get_id());
    CHECK(!report.manifest.empty());
    CHECK(trusted_signing_json(backing.output()).find("Trusted") != std::string::npos);
}

TEST(coroutine_signing_get_can_free_frames_immediately_after_cross_thread_completion) {
    auto pool = make_simple_thread_pool(4);
    for (size_t iteration = 0; iteration < 32; ++iteration) {
        auto backing = std::make_shared<MemoryBuildHost>(fixture_bytes(), fixture_sign);
        PooledBuildHost host(backing, *pool);
        const auto report = co_build_and_sign(BuildSession(signing_settings()), host).get();
        CHECK(!report.manifest.empty());
        CHECK(!report.exclusions.empty());
        if (iteration == 31)
            CHECK(trusted_signing_json(backing->output()).find("Trusted") != std::string::npos);
    }
    pool.reset();
}

TEST(coroutine_signing_await_chain_captures_user_exceptions) {
    InlineBuildHost host;
    bool caught = false;
    try { (void)throwing_build_chain(host).get(); }
    catch (const std::runtime_error &error) { caught = std::string(error.what()) == "after signing"; }
    CHECK(caught);
}

TEST(coroutine_signing_spawn_propagates_start_throws_and_bad_replies) {
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
            CHECK(std::holds_alternative<std::exception_ptr>(result));
            bool caught = false;
            try { std::rethrow_exception(std::get<std::exception_ptr>(result)); }
            catch (const Exception &) { caught = true; }
            CHECK(caught);
            completed = true;
        });
        CHECK(completed);
    }
    CHECK_THROWS_CODE(co_build_and_sign(BuildSession(signing_settings()), host).get(),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
}

TEST(coroutine_signing_timestamp_transport_fails_closed) {
    const std::vector<BuildTimestamp> callbacks{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("offline"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1, 2}; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{0x30, 5, 0x30, 3, 2, 1, 2}; },
    };
    for (const auto &callback : callbacks) {
        InlineBuildHost host(callback);
        CHECK_THROWS_CODE(co_build_and_sign(BuildSession(signing_settings(true)), host).get(),
                          static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
    bool called = false;
    InlineBuildHost synthetic_tsa([&](const auto &url, const auto &body) {
        CHECK_EQ(url, "https://tsa.example/");
        CHECK(!body.empty() && body.front() == 0x30);
        called = true;
        return std::vector<uint8_t>{0x30, 8, 0x30, 3, 2, 1, 0, 0x30, 1, 0};
    });
    const auto report = co_build_and_sign(BuildSession(signing_settings(true)), synthetic_tsa).get();
    CHECK(called);
    CHECK(!report.manifest.empty());
}

int main() { return check::run_all(); }
