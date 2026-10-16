// Stress tests for two lifetime hazards found while reviewing the async and
// coroutine signing drivers. Each test asserts the *safe* behavior, so each
// FAILS (or is flagged by TSan/ASan) while the hazard exists.
//
//   1. Destroying an in-flight coroutine task races with its wakeup.
//   2. A borrowed host destroyed after a failed build is still used by
//      requests that were already accepted by the pool.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <random>
#include <thread>

#include "contentauth/c2pa_sm_coro.hpp"
#include "contentauth/c2pa_sm_sign.hpp"
#include "contentauth/c2pa_sm_sign_async.hpp"
#include "contentauth/c2pa_sm_sign_coro.hpp"
#include "support.hpp"
#include "signing_support.hpp"

using namespace c2pa::sm;
using namespace support;

namespace {

// ---- Hazard 1 ---------------------------------------------------------------

// Completes every request on its own worker thread, so replies (and therefore
// coroutine resumes) arrive concurrently with the thread that owns the Task.
class ThreadedHost : public AsyncBuildHost {
public:
    ThreadedHost() : backing_(fixture_bytes(), fixture_sign), worker_([this] { loop(); }) {}

    ~ThreadedHost() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        ready_.notify_all();
        worker_.join();
    }

    void start(BuildRequest request, BuildCompletion done) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.emplace_back(std::move(request), std::move(done));
        }
        ready_.notify_one();
    }

private:
    void loop() {
        for (;;) {
            std::pair<BuildRequest, BuildCompletion> item;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                ready_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                if (queue_.empty()) return;
                item = std::move(queue_.front());
                queue_.pop_front();
            }
            item.second(answer(backing_, item.first));  // may resume the coroutine, on this thread
        }
    }

    MemoryBuildHost backing_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::pair<BuildRequest, BuildCompletion>> queue_;
    bool stop_ = false;
    std::thread worker_;
};

}  // namespace

// Run under TSan or ASan: destroying a suspended task while the host's thread
// is delivering the reply that resumes it frees the frame the resumer is about
// to run (or is running). `Task` has no public "start", so drive it by hand.
TEST(destroying_an_inflight_coroutine_build_does_not_race_its_wakeup) {
    std::mt19937 rng(12345);
    for (int round = 0; round < 400; ++round) {
        ThreadedHost host;
        {
            auto task = co_build_and_sign(BuildSession(signing_settings()), host);
            task.await_suspend(std::noop_coroutine()).resume();  // run to first suspension
            const auto spin = std::chrono::microseconds(rng() % 400);
            const auto until = std::chrono::steady_clock::now() + spin;
            while (std::chrono::steady_clock::now() < until) {}
        }  // ~Task: cancel while the worker may be mid-wakeup
    }
}

// ---- Hazard 2 ---------------------------------------------------------------

namespace {

// Stands in for a borrowed host whose resources vanish with it. It outlives the
// whole test so a request that arrives after the "real" host died is *counted*
// instead of being undefined behavior.
class Forwarding : public SyncBuildHost {
public:
    std::mutex mutex;
    SyncBuildHost *target = nullptr;
    std::atomic<int> after_destruction{0};

    std::vector<uint8_t> read(BuildStream s, uint64_t start, uint64_t len) override {
        return live().read(s, start, len);
    }
    uint64_t length(BuildStream s) override { return live().length(s); }
    void write(BuildStream s, uint64_t offset, const std::vector<uint8_t> &b) override {
        live().write(s, offset, b);
    }
    std::vector<uint8_t> sign(const std::string &a, const std::vector<uint8_t> &d) override {
        return live().sign(a, d);
    }

private:
    SyncBuildHost &live() {
        std::lock_guard<std::mutex> lock(mutex);
        if (!target) {
            ++after_destruction;
            throw std::runtime_error("request ran after its host was destroyed");
        }
        return *target;
    }
};

// After the 86 614-byte output read, the engine issues one batch of three
// reads (hashing the written asset). Every read in that batch fails slowly, so
// the first failure ends the build while the other two are still in the pool.
class DyingHost : public MemoryBuildHost {
public:
    explicit DyingHost(Forwarding &outer)
        : MemoryBuildHost(fixture_bytes(), fixture_sign), outer_(outer) {
        std::lock_guard<std::mutex> lock(outer_.mutex);
        outer_.target = this;
    }
    ~DyingHost() override {
        std::lock_guard<std::mutex> lock(outer_.mutex);
        outer_.target = nullptr;
    }
    std::vector<uint8_t> read(BuildStream s, uint64_t start, uint64_t len) override {
        if (len == 86614) armed_ = true;
        else if (armed_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            throw std::runtime_error("injected read failure");
        }
        return MemoryBuildHost::read(s, start, len);
    }

private:
    Forwarding &outer_;
    bool armed_ = false;
};

}  // namespace

// The natural stack layout: pool, host, adapter, then build_parallel. When the
// build throws, the host is destroyed while accepted requests are still queued.
TEST(a_failed_build_does_not_leave_requests_running_against_a_dead_borrowed_host) {
    Forwarding outer;
    auto pool = make_simple_thread_pool(4);  // destroyed last: joins leftover tasks
    int failed_builds = 0;
    for (int round = 0; round < 20; ++round) {
        try {
            DyingHost host(outer);
            PooledBuildHost adapter(outer, *pool);
            (void)build_parallel(BuildSession(signing_settings()), adapter);
        } catch (const Exception &) {
            ++failed_builds;
        }
    }
    pool.reset();  // run every task the pool accepted
    CHECK_EQ(failed_builds, 20);
    std::fprintf(stderr, "  requests that ran after their host was destroyed: %d\n",
                 outer.after_destruction.load());
    CHECK_EQ(outer.after_destruction.load(), 0);
}

// Optional argument: run only tests whose name contains it.
int main(int argc, char **argv) {
    if (argc > 1) {
        auto &tests = check::Registry::get().tests;
        std::erase_if(tests, [&](const auto &t) { return t.first.find(argv[1]) == std::string::npos; });
    }
    return check::run_all();
}
