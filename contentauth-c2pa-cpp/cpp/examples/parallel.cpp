// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The same read, three ways, against a deliberately slow "disk" (every read
// takes LATENCY): serially, with the engine's requests overlapped on a
// thread pool, and as a coroutine. Only the *host* changes; the engine and
// the answer are identical.
//
//   c2pa_sm_parallel photo.jpg [latency-ms]

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

#include "contentauth/c2pa_sm_coro.hpp"

using namespace c2pa::sm;
using Clock = std::chrono::steady_clock;

/// A file whose every read takes `latency`, and which counts how many are
/// in flight.
class SlowFile : public FileHost {
public:
    SlowFile(const char *path, std::chrono::milliseconds latency)
        : FileHost(path), latency_(latency) {}

    std::vector<uint8_t> read(uint64_t start, uint64_t len) override {
        size_t now = ++in_flight_;
        size_t seen = max_in_flight.load();
        while (now > seen && !max_in_flight.compare_exchange_weak(seen, now)) {
        }
        std::this_thread::sleep_for(latency_);
        --in_flight_;
        ++reads;
        return FileHost::read(start, len);
    }

    std::atomic<size_t> max_in_flight{0};
    std::atomic<size_t> reads{0};

private:
    std::chrono::milliseconds latency_;
    std::atomic<size_t> in_flight_{0};
};

template <class F>
static void timed(const char *label, SlowFile &file, F &&body) {
    file.max_in_flight = 0;
    file.reads = 0;
    auto start = Clock::now();
    auto reader = body();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    std::printf("%-26s %5lld ms  %3zu reads, up to %zu at once  (%s)\n", label,
                static_cast<long long>(ms), file.reads.load(), file.max_in_flight.load(),
                reader ? reader->active_label().value_or("?").c_str() : "no manifest");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s FILE [latency-ms]\n", argv[0]);
        return 2;
    }
    SlowFile file(argv[1], std::chrono::milliseconds(argc > 2 ? std::atoi(argv[2]) : 20));
    try {
        timed("serial (blocking)", file, [&] { return read(Session("image/jpeg"), file); });

        ThreadPool pool(8);
        PooledHost pooled(file, pool);
        timed("thread pool (8)", file, [&] { return read_parallel(Session("image/jpeg"), pooled); });
        timed("coroutine, same pool", file,
              [&] { return co_read(Session("image/jpeg"), pooled).get(); });

        // Many assets at once. Each coroutine runs until it must wait, then
        // costs nothing; this thread starts them all and just waits for the
        // last. Parallelism is bounded by the pool's I/O threads (8), not by
        // how many reads are in progress (kAssets) — no thread blocks inside
        // a c2pa call.
        constexpr int kAssets = 16;
        file.max_in_flight = 0;
        file.reads = 0;
        std::atomic<int> remaining{kAssets};
        auto start = Clock::now();
        for (int i = 0; i < kAssets; ++i) {
            spawn(co_read(Session("image/jpeg"), pooled), [&](Outcome<std::optional<Reader>>) {
                --remaining;
            });
        }
        while (remaining > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        std::printf("%d assets, 8 I/O threads %5lld ms  %3zu reads, up to %zu at once\n", kAssets,
                    static_cast<long long>(ms), file.reads.load(), file.max_in_flight.load());
        return 0;
    } catch (const Exception &e) {
        std::fprintf(stderr, "%s (%s)\n", e.what(), e.name().c_str());
        return 2;
    }
}
