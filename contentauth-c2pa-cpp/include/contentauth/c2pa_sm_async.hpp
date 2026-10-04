// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

/// @file c2pa_sm_async.hpp
/// @brief Asynchronous and threaded drivers for `c2pa::sm::Session` (C++17).
///
/// One idea, in three layers:
///
///  1. `AsyncHost::start(request, done)` — the only thing an asynchronous
///     host must provide: *begin* the work and call `done(reply)` whenever
///     and from whatever thread it finishes. That is the shape of an
///     io_uring completion, a libuv or asio callback, a thread-pool task,
///     a `fetch`.
///  2. `Reading` — one read in flight. It owns the `Session` and a
///     `Mailbox`; `step()` applies whatever has arrived, advances the
///     session, and starts whatever is new. **The session is only ever
///     touched by whoever calls `step()`, never by a completion** — the
///     completions merely post to the mailbox — so a session needs no lock
///     even with a dozen requests in flight on a dozen threads.
///  3. Drivers that decide *who* calls `step()` and what happens while
///     waiting: `read_parallel` (park the calling thread), `read_future`
///     (a `std::future`), and — in `c2pa_sm_coro.hpp` — `co_await`.

#ifndef CONTENTAUTH_C2PA_SM_ASYNC_HPP
#define CONTENTAUTH_C2PA_SM_ASYNC_HPP

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include "c2pa_sm.hpp"

namespace c2pa::sm {

/// @brief Called by a host, from any thread, exactly once per request.
using Completion = std::function<void(Reply)>;

/// @brief The asynchronous host: begin a request, report back when done.
///
/// `start` should return promptly. It may call `done` before returning, or
/// from another thread later. If it throws, the driver answers the request
/// with `Failed`.
class AsyncHost {
public:
    virtual ~AsyncHost() = default;
    virtual void start(const Request &request, Completion done) = 0;
};

/// @brief Thread-safe hand-off of replies from wherever they complete to
///        whoever drives the session. The only shared state in the design.
class Mailbox {
public:
    using Message = std::pair<uint64_t, Reply>;

    /// @brief Delivers a reply; callable from any thread. Wakes a waiter or
    ///        the registered waker, if any.
    void post(uint64_t id, Reply reply) {
        std::function<void()> waker;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            messages_.emplace_back(id, std::move(reply));
            waker = std::move(waker_);
            waker_ = nullptr;
        }
        cv_.notify_all();
        if (waker) {
            waker();
        }
    }

    /// @brief Takes everything that has arrived; never blocks.
    std::vector<Message> drain() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Message> out(std::make_move_iterator(messages_.begin()),
                                 std::make_move_iterator(messages_.end()));
        messages_.clear();
        return out;
    }

    /// @brief Blocks the calling thread until at least one reply is waiting.
    void wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !messages_.empty(); });
    }

    /// @brief For event loops and coroutines: arranges for `waker` to be
    ///        called, once, from whichever thread next posts a reply.
    /// @return false — and does *not* register `waker` — if a reply is
    ///         already waiting, so the caller should just `drain`.
    bool set_waker(std::function<void()> waker) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!messages_.empty()) {
            return false;
        }
        waker_ = std::move(waker);
        return true;
    }

    /// @brief Forgets a registered waker (a no-op if it already fired).
    void clear_waker() {
        std::lock_guard<std::mutex> lock(mutex_);
        waker_ = nullptr;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Message> messages_;
    std::function<void()> waker_;
};

/// @brief One read in flight against an `AsyncHost`.
///
/// Not thread-safe, by design: whoever is driving calls `step()`. What may
/// happen concurrently is everything the *host* does.
///
/// Destroying a `Reading` before it finishes cancels it. Requests already
/// started run to completion on the host (this layer cannot recall them),
/// but their completions post to a mailbox that outlives the session, so
/// nothing can arrive at freed memory — the hazard c2pa-cpp's docs warn of
/// for a progress callback that outlives its `Context`.
class Reading {
public:
    /// @param host must outlive any request it has started; it need not
    ///        outlive the `Reading` itself, since only `step` calls it.
    Reading(Session session, AsyncHost &host)
        : session_(std::move(session)), host_(&host), mailbox_(std::make_shared<Mailbox>()) {}

    Reading(Reading &&) noexcept = default;
    Reading &operator=(Reading &&) noexcept = default;

    /// @brief Applies every reply that has arrived, advances the session
    ///        once, and starts every request that is new. Never blocks.
    /// @return true when the read is complete; call `finish`.
    /// @throws Exception on a failed read, or if the session is waiting on
    ///         nothing (which would otherwise hang forever).
    bool step() {
        for (auto &[id, reply] : mailbox_->drain()) {
            session_.fulfill(id, reply);
            --in_flight_;
        }
        Step step = session_.advance();
        if (step.done) {
            return true;
        }
        detail::require_progress(!step.requests.empty() || in_flight_ > 0);
        for (const Request &request : step.requests) {
            ++in_flight_;
            max_in_flight_ = std::max(max_in_flight_, in_flight_);
            ++started_;
            const uint64_t id = request_id(request);
            Completion done = [mailbox = mailbox_, id](Reply reply) {
                mailbox->post(id, std::move(reply));
            };
            try {
                host_->start(request, done);
            } catch (const std::exception &e) {
                done(Failed{e.what()});
            } catch (...) {
                done(Failed{"unknown host error"});
            }
        }
        return false;
    }

    /// @brief Consumes the finished read. Valid only after `step()` returned
    ///        true.
    std::optional<Reader> finish() && { return std::move(session_).finish(); }

    /// @brief Where replies land; for `wait()` or `set_waker()`.
    Mailbox &mailbox() { return *mailbox_; }

    /// @brief Requests started and not yet answered.
    size_t in_flight() const { return in_flight_; }
    /// @brief The most requests that were ever outstanding at once.
    size_t max_in_flight() const { return max_in_flight_; }
    /// @brief Requests started in all.
    size_t started() const { return started_; }

private:
    Session session_;
    AsyncHost *host_;
    std::shared_ptr<Mailbox> mailbox_;
    size_t in_flight_ = 0;
    size_t max_in_flight_ = 0;
    size_t started_ = 0;
};

/// @brief Drives a read on the calling thread, which parks while the host
///        works. With a host that runs requests concurrently, the read's
///        outstanding requests overlap.
inline std::optional<Reader> read_parallel(Session session, AsyncHost &host) {
    Reading reading(std::move(session), host);
    while (!reading.step()) {
        reading.mailbox().wait();
    }
    return std::move(reading).finish();
}

/// @brief Runs a read on its own thread, as a `std::future`. The host is
///        shared so that it outlives the work however the future is used.
///        Dropping the future blocks until the read ends (a `std::async`
///        rule); to abandon a read promptly, drive a `Reading` yourself and
///        destroy it.
inline std::future<std::optional<Reader>> read_future(Session session,
                                                     std::shared_ptr<AsyncHost> host) {
    return std::async(std::launch::async,
                      [session = std::move(session), host = std::move(host)]() mutable {
                          return read_parallel(std::move(session), *host);
                      });
}

/// @brief A minimal fixed-size thread pool: enough to run a host's
///        blocking calls concurrently. Joins on destruction after running
///        everything queued.
class ThreadPool {
public:
    explicit ThreadPool(size_t threads) {
        for (size_t i = 0; i < std::max<size_t>(threads, 1); ++i) {
            workers_.emplace_back([this] { run(); });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        cv_.notify_all();
        for (auto &worker : workers_) {
            worker.join();
        }
    }

    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    /// @brief Queues `task`.
    void post(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_.push_back(std::move(task));
        }
        cv_.notify_one();
    }

private:
    void run() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
                if (tasks_.empty()) {
                    return;  // stopping, and drained
                }
                task = std::move(tasks_.front());
                tasks_.pop_front();
            }
            task();
        }
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;
};

/// @brief Adapts any thread-safe `SyncHost` into an `AsyncHost` by running
///        each request on a `ThreadPool`: the one-line way to make an
///        existing blocking host parallel. Both must outlive every read.
class PooledHost : public AsyncHost {
public:
    PooledHost(SyncHost &host, ThreadPool &pool) : host_(host), pool_(pool) {}

    void start(const Request &request, Completion done) override {
        pool_.post([this, request, done = std::move(done)] { done(answer(host_, request)); });
    }

private:
    SyncHost &host_;
    ThreadPool &pool_;
};

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_C2PA_SM_ASYNC_HPP
