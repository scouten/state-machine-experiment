#include "contentauth/c2pa_sm_sign_coro.hpp"

namespace c2pa::sm {

namespace {

struct BuildWake {
    std::mutex mutex;
    std::coroutine_handle<> continuation;

    void disarm();
    void resume();
};

void BuildWake::disarm() {
    std::lock_guard<std::mutex> lock(mutex);
    continuation = {};
}

void BuildWake::resume() {
    std::coroutine_handle<> next;
    {
        std::lock_guard<std::mutex> lock(mutex);
        next = std::exchange(continuation, {});
    }
    if (next) next.resume();
}

class NextBuildReply {
public:
    explicit NextBuildReply(BuildMailbox &mailbox);
    ~NextBuildReply();
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> continuation);
    void await_resume() const noexcept;

private:
    BuildMailbox &mailbox_;
    std::shared_ptr<BuildWake> wake_ = std::make_shared<BuildWake>();
};

NextBuildReply::NextBuildReply(BuildMailbox &mailbox) : mailbox_(mailbox) {}

NextBuildReply::~NextBuildReply() {
    wake_->disarm();
    mailbox_.clear_waker();
}

bool NextBuildReply::await_ready() const noexcept { return false; }

bool NextBuildReply::await_suspend(std::coroutine_handle<> continuation) {
    auto wake = wake_;
    auto *mailbox = &mailbox_;
    wake->continuation = continuation;
    return mailbox->set_waker([wake = std::move(wake)] { wake->resume(); });
}

void NextBuildReply::await_resume() const noexcept {}

}

Task<SignReport> co_build_and_sign(BuildSession session, AsyncBuildHost &host) {
    Building building(std::move(session), host);
    while (!building.step()) {
        co_await NextBuildReply(building.mailbox());
    }
    co_return std::move(building).finish();
}

}  // namespace c2pa::sm