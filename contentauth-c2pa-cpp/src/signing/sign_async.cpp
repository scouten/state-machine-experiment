#include "contentauth/c2pa_sm_sign_async.hpp"
#include "support/scope_exit.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_set>

namespace c2pa::sm {

namespace {

[[noreturn]] void invalid_build(const char *message) {
    throw Exception(ErrorCode::InvalidArgument, "Build(InvalidArgument)", message);
}

class Driving {
public:
    explicit Driving(std::atomic_flag &active) : active_(active) {
        if (active_.test_and_set()) invalid_build("concurrent or reentrant build driver");
    }

    ~Driving() { active_.clear(); }

private:
    std::atomic_flag &active_;
};

}

AsyncBuildHost::~AsyncBuildHost() = default;

struct BuildMailbox::State {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Message> messages;
    std::function<void()> waker;
    bool cancelled = false;
};

BuildMailbox::BuildMailbox() : state_(std::make_unique<State>()) {}

BuildMailbox::~BuildMailbox() = default;

void BuildMailbox::post(uint64_t id, BuildReply reply) {
    std::function<void()> waker;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->cancelled) return;
        state_->messages.emplace_back(id, std::move(reply));
        waker.swap(state_->waker);
    }
    state_->ready.notify_all();
    if (waker) { try { waker(); } catch (...) {} }
}

std::vector<BuildMailbox::Message> BuildMailbox::drain() {
    std::lock_guard<std::mutex> lock(state_->mutex);
    std::vector<Message> messages(std::make_move_iterator(state_->messages.begin()),
                                  std::make_move_iterator(state_->messages.end()));
    state_->messages.clear();
    return messages;
}

void BuildMailbox::wait() {
    std::unique_lock<std::mutex> lock(state_->mutex);
    state_->ready.wait(lock, [this] { return state_->cancelled || !state_->messages.empty(); });
}

bool BuildMailbox::set_waker(std::function<void()> waker) {
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->cancelled || !state_->messages.empty()) return false;
    state_->waker.swap(waker);
    return true;
}

void BuildMailbox::clear_waker() {
    std::function<void()> discarded;
    { std::lock_guard<std::mutex> lock(state_->mutex); discarded.swap(state_->waker); }
}

void BuildMailbox::cancel() {
    std::function<void()> discarded;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->cancelled = true;
        state_->messages.clear();
        discarded.swap(state_->waker);
    }
    state_->ready.notify_all();
}

struct Building::State {
    struct Work {
        std::mutex mutex;
        std::condition_variable ready;
        size_t outstanding = 0;
    };
    BuildSession session;
    AsyncBuildHost *host;
    std::shared_ptr<BuildMailbox> mailbox = std::make_shared<BuildMailbox>();
    std::unordered_set<uint64_t> pending;
    std::atomic_flag active = ATOMIC_FLAG_INIT;
    std::exception_ptr failure;
    std::shared_ptr<Work> work = std::make_shared<Work>();
    size_t started = 0, maximum = 0;
    bool complete = false, finished = false;

    State(BuildSession input, AsyncBuildHost &owner) : session(std::move(input)), host(&owner) {}

    ~State() { mailbox->cancel(); }
};

Building::Building(BuildSession session, AsyncBuildHost &host)
    : state_(std::make_unique<State>(std::move(session), host)) {}

Building::~Building() = default;

Building::Building(Building &&) noexcept = default;

Building &Building::operator=(Building &&) noexcept = default;

Building::State &Building::state() const {
    if (!state_) invalid_build("moved-from build operation");
    return *state_;
}

bool Building::step() {
    auto &current = state();
    Driving driving(current.active);
    if (current.finished) invalid_build("finished build operation");
    if (current.failure) std::rethrow_exception(current.failure);
    if (current.complete) return true;
    try {
        for (auto &[id, reply] : current.mailbox->drain()) {
            if (!current.pending.count(id)) invalid_build("unknown or duplicate build reply ID");
            current.session.fulfill(id, std::move(reply));
            current.pending.erase(id);
        }
        auto next = current.session.advance();
        current.complete = next.done;
        if (next.done) return true;
        if (next.requests.empty() && current.pending.empty()) invalid_build("stalled build operation");
        for (auto &request : next.requests) {
            const auto id = request_id(request);
            if (!current.pending.insert(id).second) invalid_build("duplicate build request ID");
            ++current.started;
            current.maximum = std::max(current.maximum, current.pending.size());
            auto delivered = std::make_shared<std::atomic<bool>>(false);
            BuildCompletion done = [mailbox = current.mailbox, delivered, work = current.work, id](BuildReply reply) {
                if (delivered->exchange(true)) return;
                auto completion_guard = detail::make_scope_exit([work]() noexcept {
                    std::lock_guard<std::mutex> lock(work->mutex);
                    --work->outstanding;
                    work->ready.notify_all();
                });
                mailbox->post(id, std::move(reply));
            };
            {
                std::lock_guard<std::mutex> lock(current.work->mutex);
                ++current.work->outstanding;
            }
            try { current.host->start(std::move(request), done); }
            catch (const std::exception &error) { done(Failed{error.what()}); }
            catch (...) { done(Failed{"unknown host error"}); }
        }
        return false;
    } catch (...) {
        current.failure = std::current_exception();
        current.mailbox->cancel();
        throw;
    }
}

SignReport Building::finish() && {
    auto &current = state();
    Driving driving(current.active);
    if (current.finished) invalid_build("finished build operation");
    current.finished = true;
    current.mailbox->cancel();
    if (current.failure) std::rethrow_exception(current.failure);
    return std::move(current.session).finish();
}

BuildMailbox &Building::mailbox() { return *state().mailbox; }

size_t Building::in_flight() const { return state().pending.size(); }

size_t Building::max_in_flight() const { return state().maximum; }

size_t Building::started() const { return state().started; }

void Building::wait() {
    auto work = state().work;
    std::unique_lock<std::mutex> lock(work->mutex);
    work->ready.wait(lock, [&] { return work->outstanding == 0; });
}

SignReport build_parallel(BuildSession session, AsyncBuildHost &host) {
    Building building(std::move(session), host);
    try {
        while (!building.step()) building.mailbox().wait();
    } catch (...) {
        building.wait();
        throw;
    }
    building.wait();
    return std::move(building).finish();
}

std::future<SignReport> build_future(BuildSession session, std::shared_ptr<AsyncBuildHost> host) {
    if (!host) invalid_build("null async build host");
    return std::async(std::launch::async, [session = std::move(session), host = std::move(host)]() mutable {
        return build_parallel(std::move(session), *host);
    });
}

struct PooledBuildHost::State {
    std::shared_ptr<SyncBuildHost> owner;
    SyncBuildHost *host;
    std::mutex mutex;
    std::deque<std::pair<BuildRequest, BuildCompletion>> queue;
    bool scheduled = false;

    explicit State(SyncBuildHost &input) : host(&input) {}

    explicit State(std::shared_ptr<SyncBuildHost> input) : owner(std::move(input)), host(owner.get()) {}
};

PooledBuildHost::PooledBuildHost(SyncBuildHost &host, ThreadPool &pool)
    : state_(std::make_shared<State>(host)), pool_(&pool) {}

PooledBuildHost::PooledBuildHost(std::shared_ptr<SyncBuildHost> host, ThreadPool &pool)
    : state_(std::make_shared<State>(std::move(host))), pool_(&pool) {
    if (!state_->host) invalid_build("null pooled build host");
}

PooledBuildHost::~PooledBuildHost() = default;

void PooledBuildHost::start(BuildRequest request, BuildCompletion done) {
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->queue.emplace_back(std::move(request), std::move(done));
        if (state_->scheduled) return;
        state_->scheduled = true;
    }
    try {
        pool_->post([state = state_] {
            for (;;) {
                std::pair<BuildRequest, BuildCompletion> next;
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (state->queue.empty()) {
                        state->scheduled = false;
                        return;
                    }
                    next = std::move(state->queue.front());
                    state->queue.pop_front();
                }
                auto reply = answer(*state->host, next.first);
                try { next.second(std::move(reply)); } catch (...) {}
            }
        });
    } catch (...) {
        // A rejected drain also owns requests enqueued by concurrent callers.
        // Complete every one, rather than stranding them behind scheduled=true.
        std::deque<std::pair<BuildRequest, BuildCompletion>> rejected;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            rejected.swap(state_->queue);
            state_->scheduled = false;
        }
        std::string message = "pool rejected build work";
        try { throw; }
        catch (const std::exception &error) { message = error.what(); }
        catch (...) {}
        for (auto &entry : rejected) {
            try { entry.second(Failed{message}); } catch (...) {}
        }
    }
}

}  // namespace c2pa::sm