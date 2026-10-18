#include "contentauth/c2pa_sm_sign_coro.hpp"

namespace c2pa::sm {

namespace {

class NextBuildReply {
public:
    explicit NextBuildReply(BuildMailbox &mailbox);
    ~NextBuildReply();
    bool await_ready() const noexcept;
    template <class Promise>
    bool await_suspend(std::coroutine_handle<Promise> continuation) {
        return mailbox_.set_waker(detail::coroutine_waker(continuation));
    }
    void await_resume() const noexcept;

private:
    BuildMailbox &mailbox_;
};

NextBuildReply::NextBuildReply(BuildMailbox &mailbox) : mailbox_(mailbox) {}

NextBuildReply::~NextBuildReply() {
    mailbox_.clear_waker();
}

bool NextBuildReply::await_ready() const noexcept { return false; }

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