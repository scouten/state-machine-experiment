// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The coroutine driver, which needs C++20.

#include <set>

#include "contentauth/c2pa_sm_coro.hpp"
#include "support.hpp"

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
    ThreadPool pool(8);
    PooledHost host(slow, pool);

    auto reader = co_read(Session("image/jpeg"), host).get();
    CHECK_EQ(json_of(reader), reference_json());
    CHECK(slow.max_in_flight() > 1);
}

TEST(coroutines_compose_and_propagate_exceptions) {
    MemoryHost backing = fixture_host();
    ThreadPool pool(4);
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
        ThreadPool pool{4};
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
    ThreadPool pool(8);
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

int main() { return check::run_all(); }
