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

/// @file thread_pool.hpp
/// @brief The scheduling interface behind `PooledHost`, and factories for the
///        pools this library ships.

#ifndef CONTENTAUTH_THREAD_POOL_HPP
#define CONTENTAUTH_THREAD_POOL_HPP

#include <cstddef>
#include <functional>
#include <memory>

namespace c2pa::sm {

/// @brief Runs tasks on threads the pool owns. Applications with their own
///        executor implement this and hand it to `PooledHost`.
///
/// `post` may be called from any thread, including from a running task.
/// Every accepted task runs exactly once, in no particular order. Tasks must
/// not let an exception escape. Destroying a pool runs everything already
/// posted first; callers must stop posting before then, and must not destroy
/// a pool from one of its own tasks.
class ThreadPool {
public:
    virtual ~ThreadPool() = default;

    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    /// @brief Queues `task` and returns without waiting for it.
    virtual void post(std::function<void()> task) = 0;

protected:
    ThreadPool() = default;
};

/// @brief A portable pool of exactly `threads` workers (at least one) sharing
///        one FIFO queue.
std::unique_ptr<ThreadPool> make_simple_thread_pool(size_t threads);

#if defined(__APPLE__)
/// @brief A pool backed by Grand Central Dispatch. GCD decides how many threads
///        run at once, so there is no worker count to give.
std::unique_ptr<ThreadPool> make_apple_thread_pool();
#endif

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_THREAD_POOL_HPP
