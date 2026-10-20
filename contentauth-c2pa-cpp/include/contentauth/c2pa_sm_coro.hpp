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

/// @file c2pa_sm_coro.hpp
/// @brief C++20 coroutine driver: `co_await c2pa::sm::co_read(...)`.
///
/// A coroutine is the natural way to *be* a sans-I/O driver: the loop
/// `step; suspend until a reply arrives; repeat` is straight-line code, the
/// session lives in the coroutine frame, and nothing blocks a thread while
/// the host's I/O is outstanding.
///
/// No scheduler is imposed. A suspended `co_read` is resumed by whichever
/// thread posts the reply that unblocks it (an io_uring reaper, a thread
/// pool worker, the test's own loop), so the session migrates between
/// threads — never used by two at once, because a resume happens only once
/// per suspension. This works because errors are values and the library has
/// no thread-local state; a binding built on a "last error on this thread"
/// would break the first time a coroutine resumed elsewhere.

#ifndef CONTENTAUTH_C2PA_SM_CORO_HPP
#define CONTENTAUTH_C2PA_SM_CORO_HPP

#if !defined(__cpp_impl_coroutine) && !defined(__cpp_coroutines)
#error "c2pa_sm_coro.hpp needs C++20 coroutines (compile with -std=c++20)"
#endif

#include <coroutine>
#include <exception>
#include <memory>
#include <variant>

#include "c2pa_sm_async.hpp"

namespace c2pa::sm {

namespace detail {

// Nested Tasks share an execution gate: a reply can transfer into an awaiting
// frame, so guarding only the directly resumed frame would not be sufficient.
struct CoroutineLifetime {
    std::shared_ptr<std::recursive_mutex> gate = std::make_shared<std::recursive_mutex>();
    bool alive = true;
};

template <class Promise>
std::function<void()> coroutine_waker(std::coroutine_handle<Promise> handle) {
    if constexpr (requires { handle.promise().lifetime; }) {
        auto lifetime = handle.promise().lifetime;
        return [lifetime = std::move(lifetime), handle] {
            std::lock_guard<std::recursive_mutex> lock(*lifetime->gate);
            if (lifetime->alive) handle.resume();
        };
    } else {
        // Foreign coroutine owners must serialize destruction themselves.
        return [handle] { handle.resume(); };
    }
}

}  // namespace detail

/// @brief A lazy coroutine result: starts when awaited (or `get()` called).
///
/// Awaiting resumes the awaiter on whatever thread completed the task.
/// Destruction cancels a suspended task and waits for a callback-driven resume
/// already executing. Task objects themselves still require serialized access.
template <class T>
class Task {
public:
    struct promise_type;
    using Handle = std::coroutine_handle<promise_type>;

    struct promise_type {
        std::variant<std::monostate, T, std::exception_ptr> result;
        std::coroutine_handle<> continuation;
        std::shared_ptr<detail::CoroutineLifetime> lifetime =
            std::make_shared<detail::CoroutineLifetime>();

        // Used only by get(): signalled when the task completes with no
        // coroutine awaiting it. Held by shared pointer, *not* inline in the
        // frame, so that the completing thread never touches frame memory
        // after it has signalled: the waiter may destroy the frame the
        // instant it wakes.
        struct Sync {
            std::mutex mutex;
            std::condition_variable cv;
            bool finished = false;
        };
        std::shared_ptr<Sync> sync = std::make_shared<Sync>();

        Task get_return_object() { return Task(Handle::from_promise(*this)); }
        std::suspend_always initial_suspend() noexcept { return {}; }

        struct Final : std::suspend_always {
            std::coroutine_handle<> await_suspend(Handle h) noexcept {
                promise_type &p = h.promise();
                if (p.continuation) {
                    return p.continuation;  // symmetric transfer to the awaiter
                }
                // From here on, only this local copy is touched — never `p`
                // or `this`, which live in a frame get() may now free.
                std::shared_ptr<Sync> sync = p.sync;
                {
                    std::lock_guard<std::mutex> lock(sync->mutex);
                    sync->finished = true;
                    sync->cv.notify_all();
                }
                return std::noop_coroutine();
            }
        };
        Final final_suspend() noexcept { return {}; }

        void return_value(T value) { result.template emplace<1>(std::move(value)); }
        void unhandled_exception() { result.template emplace<2>(std::current_exception()); }
    };

    Task(Task &&other) noexcept
        : handle_(std::exchange(other.handle_, {})), lifetime_(std::move(other.lifetime_)) {}
    Task &operator=(Task &&other) noexcept {
        if (this != &other) {
            destroy();
            handle_ = std::exchange(other.handle_, {});
            lifetime_ = std::move(other.lifetime_);
        }
        return *this;
    }
    Task(const Task &) = delete;
    Task &operator=(const Task &) = delete;
    ~Task() { destroy(); }

    bool await_ready() const noexcept { return false; }
    template <class Promise>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> awaiter) noexcept {
        if constexpr (requires { awaiter.promise().lifetime; }) {
            lifetime_->gate = awaiter.promise().lifetime->gate;
        }
        handle_.promise().continuation = awaiter;
        return handle_;
    }
    T await_resume() { return take(); }

    /// @brief Runs the task and blocks the calling thread until it ends —
    ///        for `main()` and tests; inside a coroutine, `co_await` instead.
    T get() && {
        // Take our own reference before resuming: once the task completes
        // on another thread, the frame (and its promise) may not be touched
        // except through what we hold.
        std::shared_ptr<typename promise_type::Sync> sync = handle_.promise().sync;
        {
            std::lock_guard<std::recursive_mutex> lock(*lifetime_->gate);
            handle_.resume();
        }
        {
            std::unique_lock<std::mutex> lock(sync->mutex);
            sync->cv.wait(lock, [&sync] { return sync->finished; });
        }
        std::lock_guard<std::recursive_mutex> lock(*lifetime_->gate);
        return take();
    }

private:
    explicit Task(Handle h) : handle_(h), lifetime_(h.promise().lifetime) {}

    T take() {
        auto &result = handle_.promise().result;
        if (result.index() == 2) {
            std::rethrow_exception(std::get<2>(result));
        }
        return std::move(std::get<1>(result));
    }

    void destroy() {
        if (handle_) {
            // Keep the gate alive even if nested destruction releases the
            // promise's final reference while a callback is returning.
            auto lifetime = lifetime_;
            std::lock_guard<std::recursive_mutex> lock(*lifetime->gate);
            lifetime->alive = false;
            handle_.destroy();
            handle_ = {};
        }
    }

    Handle handle_;
    std::shared_ptr<detail::CoroutineLifetime> lifetime_;
};

/// @brief What a `spawn`ed task produced: its value, or what it threw.
template <class T>
using Outcome = std::variant<T, std::exception_ptr>;

namespace detail {

/// A coroutine that starts at once, belongs to no one, and frees itself.
struct Detached {
    struct promise_type {
        Detached get_return_object() { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() { std::terminate(); }
    };
};

template <class T, class F>
Detached run_detached(Task<T> task, F on_done) {
    // Parameters live in the coroutine frame, so `task` outlives every
    // suspension below.
    try {
        T value = co_await task;
        on_done(Outcome<T>(std::in_place_index<0>, std::move(value)));
    } catch (...) {
        on_done(Outcome<T>(std::in_place_index<1>, std::current_exception()));
    }
}

}  // namespace detail

/// @brief Starts `task` at once, without blocking, and later calls
///        `on_done(Outcome<T>)` — on whichever thread finishes it.
///
/// This is how one thread starts a thousand reads: each runs until it must
/// wait for the host, then costs nothing until a reply arrives. (`on_done`
/// must not throw.)
template <class T, class F>
void spawn(Task<T> task, F on_done) {
    detail::run_detached<T, F>(std::move(task), std::move(on_done));
}

/// @brief Suspends until a reply is waiting in `mailbox`; resumes on the
///        thread that posted it.
struct NextReply {
    Mailbox &mailbox;
    bool await_ready() const noexcept { return false; }
    template <class Promise>
    bool await_suspend(std::coroutine_handle<Promise> h) {
        // false (resume at once) if a reply already arrived
        return mailbox.set_waker(detail::coroutine_waker(h));
    }
    void await_resume() const noexcept {}
    // Destroying a suspended coroutine destroys this awaiter: make sure no
    // later reply tries to resume the dead frame.
    ~NextReply() { mailbox.clear_waker(); }
};

/// @brief Reads one asset, suspending (not blocking) while the host works.
///
/// `host` must outlive the task. Destroying a suspended task cancels the
/// read: requests the host has started run on, and their completions land
/// harmlessly in the mailbox. Destruction synchronizes with callback-driven
/// resumption, including nested Tasks. A non-Task coroutine awaiting this Task
/// must externally serialize destruction of its own frame with resumption.
inline Task<std::optional<Reader>> co_read(Session session, AsyncHost &host) {
    Reading reading(std::move(session), host);
    while (!reading.step()) {
        co_await NextReply{reading.mailbox()};
    }
    co_return std::move(reading).finish();
}

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_C2PA_SM_CORO_HPP
