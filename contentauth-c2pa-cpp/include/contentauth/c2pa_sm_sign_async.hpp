#ifndef CONTENTAUTH_C2PA_SM_SIGN_ASYNC_HPP
#define CONTENTAUTH_C2PA_SM_SIGN_ASYNC_HPP

#include "c2pa_sm_sign.hpp"
#include "thread_pool.hpp"
#include <future>

namespace c2pa::sm {

/// Callable on any thread; only the first reply (or start failure) is accepted.
using BuildCompletion = std::function<void(BuildReply)>;

/// Takes ownership of each request. start returns promptly and may complete inline.
class AsyncBuildHost {
public:
    virtual ~AsyncBuildHost();
    virtual void start(BuildRequest request, BuildCompletion done) = 0;
};

/// Thread-safe reply queue. Wakers run once, outside the lock; exceptions are ignored.
class BuildMailbox {
public:
    using Message = std::pair<uint64_t, BuildReply>;
    BuildMailbox();
    ~BuildMailbox();
    void post(uint64_t id, BuildReply reply);
    std::vector<Message> drain();
    /// Returns when a reply arrives or the operation is cancelled.
    void wait();
    /// False if already ready or cancelled; the caller should drive again.
    bool set_waker(std::function<void()> waker);
    void clear_waker();
private:
    friend class Building;
    void cancel();
    struct State;
    std::unique_ptr<State> state_;
};

/// Move-only single driver; callbacks only enqueue and survive cancellation safely.
/// step/finish overlap or reentry throws InvalidArgument. Other access, moves and
/// destruction require external serialization. The driver may migrate between threads.
/// The host and its resources must outlive every started request, even after cancellation.
class Building {
public:
    Building(BuildSession session, AsyncBuildHost &host);
    ~Building();
    Building(Building &&) noexcept;
    Building &operator=(Building &&) noexcept;
    Building(const Building &) = delete;
    Building &operator=(const Building &) = delete;
    /// Nonblocking pump; true remains true until finish. Protocol errors are terminal.
    bool step();
    /// Consumes the session, including on error; requires completion.
    SignReport finish() &&;
    BuildMailbox &mailbox();
    size_t in_flight() const;
    size_t max_in_flight() const;
    size_t started() const;
private:
    struct State;
    std::unique_ptr<State> state_;
    State &state() const;
};

/// Parks the caller while the host works; never polls or runs blocking host work itself.
SignReport build_parallel(BuildSession session, AsyncBuildHost &host);
/// Owns a driver thread and host until completion. get propagates exceptions;
/// destroying the last future waits for the driver, as required by std::async.
std::future<SignReport> build_future(BuildSession session, std::shared_ptr<AsyncBuildHost> host);

/// Serializes all work through this adapter, including mutable buffers/seekable streams.
/// Use one adapter per host; no direct or other-adapter access while tasks are pending.
/// Tasks retain adapter state, not this. Borrowed host/pool must outlive queued work;
/// the shared overload retains the host. Pool destruction joins accepted tasks.
class PooledBuildHost : public AsyncBuildHost {
public:
    PooledBuildHost(SyncBuildHost &host, ThreadPool &pool);
    PooledBuildHost(std::shared_ptr<SyncBuildHost> host, ThreadPool &pool);
    ~PooledBuildHost() override;
    void start(BuildRequest request, BuildCompletion done) override;
private:
    struct State;
    std::shared_ptr<State> state_;
    ThreadPool *pool_;
};

}  // namespace c2pa::sm
#endif