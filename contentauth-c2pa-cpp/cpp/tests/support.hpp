// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#ifndef C2PA_SM_SUPPORT_HPP
#define C2PA_SM_SUPPORT_HPP

#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <mutex>
#include <thread>

#include "check.hpp"
#include "contentauth/c2pa_sm_async.hpp"

namespace support {

/// Inside every certificate's validity window, and not the wall clock.
constexpr int64_t kNow = 1'800'000'000;

inline std::vector<uint8_t> fixture_bytes() {
    std::ifstream f(C2PA_SM_FIXTURE, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

inline c2pa::sm::MemoryHost fixture_host() {
    return c2pa::sm::MemoryHost(fixture_bytes(), kNow);
}

/// An in-memory asset whose reads take real time and which records how many
/// were in flight at once — the host-side evidence that the engine's
/// requests overlapped.
class SlowHost : public c2pa::sm::MemoryHost {
public:
    explicit SlowHost(std::chrono::milliseconds delay)
        : MemoryHost(fixture_bytes(), kNow), delay_(delay) {}

    std::vector<uint8_t> read(uint64_t start, uint64_t len) override {
        size_t now = ++in_flight_;
        size_t seen = max_in_flight_.load();
        while (now > seen && !max_in_flight_.compare_exchange_weak(seen, now)) {
        }
        std::this_thread::sleep_for(delay_);
        --in_flight_;
        ++reads_;
        return MemoryHost::read(start, len);
    }

    size_t max_in_flight() const { return max_in_flight_; }
    size_t reads() const { return reads_; }

private:
    std::chrono::milliseconds delay_;
    std::atomic<size_t> in_flight_{0};
    std::atomic<size_t> max_in_flight_{0};
    std::atomic<size_t> reads_{0};
};

/// An asynchronous host with no threads at all: it parks every request, and
/// the *test* decides which completes next, and when. This is what an event
/// loop's I/O backend looks like from the session's side.
class ManualHost : public c2pa::sm::AsyncHost {
public:
    explicit ManualHost(c2pa::sm::SyncHost &backing) : backing_(backing) {}

    void start(const c2pa::sm::Request &request, c2pa::sm::Completion done) override {
        parked_.push_back({request, std::move(done)});
    }

    size_t parked() const { return parked_.size(); }

    /// Completes the `index`th parked request (answered by the backing host).
    void complete(size_t index) {
        auto entry = std::move(parked_[index]);
        parked_.erase(parked_.begin() + static_cast<std::ptrdiff_t>(index));
        entry.done(c2pa::sm::answer(backing_, entry.request));
    }

private:
    struct Parked {
        c2pa::sm::Request request;
        c2pa::sm::Completion done;
    };
    c2pa::sm::SyncHost &backing_;
    std::vector<Parked> parked_;
};

inline std::string json_of(const std::optional<c2pa::sm::Reader> &reader) {
    return reader ? reader->json() : std::string();
}

}  // namespace support

#endif
