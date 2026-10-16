// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The core and the thread-based drivers, built as C++17 on purpose.

#include <cstdlib>
#include <sstream>
#include <type_traits>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#if defined(__unix__) || defined(__APPLE__)
#include <csignal>
#include <sys/resource.h>
#include <unistd.h>
#endif

#include "contentauth/c2pa_sm_sign.hpp"
#include "contentauth/c2pa_sm_sign_async.hpp"
#include "contentauth_c2pa_sm_sign.h"
#include "fixtures.hpp"
#include "support.hpp"
#include "signing_support.hpp"

using namespace c2pa::sm;
using namespace support;

TEST(build_session_is_move_only_and_rejects_invalid_settings) {
    static_assert(!std::is_copy_constructible_v<BuildSession>);
    static_assert(!std::is_copy_assignable_v<BuildSession>);
    static_assert(std::is_nothrow_move_constructible_v<BuildSession>);
    static_assert(std::is_nothrow_move_assignable_v<BuildSession>);
    bool rejected = false;
    try {
        BuildSession session(BuildSettings{});
    } catch (const Exception &) {
        rejected = true;
    }
    CHECK(rejected);
}

TEST(build_settings_reject_embedded_nuls_without_truncation) {
    for (int field = 0; field < 3; ++field) {
        auto settings = signing_settings();
        auto &value = field == 0 ? settings.definition_json : field == 1 ? settings.format : settings.algorithm;
        value.push_back('\0');
        value += "ignored suffix";
        CHECK_THROWS_CODE(BuildSession(settings), ErrorCode::InvalidArgument);
    }
}

TEST(async_build_rejects_overlapping_driver_calls_without_consuming_the_session) {
    struct BlockingStart : ManualBuildHost {
        std::mutex mutex;
        std::condition_variable ready;
        bool entered = false, released = false;
        void start(BuildRequest request, BuildCompletion done) override {
            {
                std::unique_lock<std::mutex> lock(mutex);
                entered = true;
                ready.notify_all();
                ready.wait(lock, [&] { return released; });
            }
            ManualBuildHost::start(std::move(request), std::move(done));
        }
    } host;
    Building building(BuildSession(signing_settings()), host);
    std::exception_ptr driver_error;
    std::thread driver([&] {
        try { building.step(); } catch (...) { driver_error = std::current_exception(); }
    });
    {
        std::unique_lock<std::mutex> lock(host.mutex);
        host.ready.wait(lock, [&] { return host.entered; });
    }
    CHECK_THROWS_CODE(building.step(), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    { std::lock_guard<std::mutex> lock(host.mutex); host.released = true; }
    host.ready.notify_all();
    driver.join();
    CHECK(!driver_error);
    host.deliver();
    while (!building.step()) host.deliver();
    CHECK(!std::move(building).finish().manifest.empty());
    CHECK(trusted_signing_json(host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(async_builds_interleave_without_redispatch_or_empty_batch_completion) {
    ManualBuildHost first_host, second_host;
    Building first(BuildSession(signing_settings()), first_host);
    Building second(BuildSession(signing_settings()), second_host);
    bool first_done = false, second_done = false;
    while (!first_done || !second_done) {
        if (!first_done) first_done = first.step();
        if (!second_done) second_done = second.step();
        if (!first_done) {
            const auto count = first.started();
            CHECK(!first.step());
            CHECK_EQ(first.started(), count);
        }
        first_host.deliver();
        second_host.deliver();
    }
    CHECK(!std::move(first).finish().manifest.empty());
    CHECK(!std::move(second).finish().manifest.empty());
    CHECK(trusted_signing_json(first_host.backing.output()).find("Trusted") != std::string::npos);
    CHECK(trusted_signing_json(second_host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(async_build_moves_cancel_late_callbacks_and_preserve_request_storage) {
    static_assert(!std::is_copy_constructible_v<Building>);
    static_assert(std::is_nothrow_move_assignable_v<Building>);
    ManualBuildHost host;
    {
        Building original(BuildSession(signing_settings()), host);
        CHECK(!original.step());
        Building moved(std::move(original));
        CHECK_THROWS_CODE(original.step(), ErrorCode::InvalidArgument);
        Building assigned(BuildSession(signing_settings()), host);
        assigned = std::move(moved);
        CHECK_THROWS_CODE(moved.step(), ErrorCode::InvalidArgument);
        CHECK(assigned.in_flight() > 0);
        CHECK_EQ(assigned.max_in_flight(), assigned.in_flight());
        CHECK(assigned.mailbox().set_waker([] { throw std::runtime_error("cancelled waker ran"); }));
    }
    host.deliver();
    CHECK(host.pending.empty());
}

TEST(build_mailbox_wakers_cover_delivery_registration_race_and_reentry) {
    for (int iteration = 0; iteration < 32; ++iteration) {
        BuildMailbox mailbox;
        std::atomic<int> wakes{0};
        std::thread delivery([&] { mailbox.post(7, Length{9}); });
        const bool registered = mailbox.set_waker([&] { ++wakes; mailbox.clear_waker(); });
        delivery.join();
        CHECK_EQ(wakes.load(), registered ? 1 : 0);
        mailbox.wait();
        CHECK(!mailbox.set_waker([] {}));
        CHECK_EQ(mailbox.drain().size(), size_t{1});
        CHECK(mailbox.set_waker([&] { ++wakes; }));
        mailbox.clear_waker();
        mailbox.post(8, Written{});
        CHECK_EQ(wakes.load(), registered ? 1 : 0);
    }
}

TEST(build_mailbox_preserves_replies_when_wakers_throw_and_discards_them_on_cancel) {
    BuildMailbox mailbox;
    for (bool standard_error : {false, true}) {
        int wakes = 0;
        CHECK(mailbox.set_waker([&] {
            ++wakes;
            if (standard_error) throw std::runtime_error("waker failed");
            throw 42;
        }));
        mailbox.post(7, Length{9});
        mailbox.wait();
        const auto messages = mailbox.drain();
        CHECK_EQ(wakes, 1);
        CHECK_EQ(messages.size(), size_t{1});
        CHECK_EQ(messages.front().first, uint64_t{7});
        CHECK_EQ(std::get<Length>(messages.front().second).value, uint64_t{9});
        CHECK(mailbox.drain().empty());
    }
    ManualBuildHost host;
    Building building(BuildSession(signing_settings()), host);
    auto &cancelled = building.mailbox();
    int wakes = 0;
    CHECK(cancelled.set_waker([&] { ++wakes; }));
    CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    cancelled.wait();
    CHECK(!cancelled.set_waker([&] { ++wakes; }));
    cancelled.post(8, Written{});
    CHECK(cancelled.drain().empty());
    CHECK_EQ(wakes, 0);
    CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
}

TEST(build_mailbox_wait_blocks_until_a_reply_or_cancellation) {
    for (bool cancel : {false, true}) {
        ManualBuildHost host;
        Building building(BuildSession(signing_settings()), host);
        auto &mailbox = building.mailbox();
        std::promise<void> entered;
        auto started = entered.get_future();
        auto waiter = std::async(std::launch::async, [&] {
            entered.set_value();
            mailbox.wait();
        });
        started.get();
        CHECK(waiter.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
        if (cancel) CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
        else mailbox.post(7, Length{9});
        waiter.get();
        CHECK_EQ(mailbox.drain().size(), cancel ? size_t{0} : size_t{1});
    }
}

TEST(async_build_protocol_errors_are_terminal_instead_of_hanging) {
    for (bool bad_id : {false, true}) {
        ManualBuildHost host;
        Building building(BuildSession(signing_settings()), host);
        CHECK(!building.step());
        building.mailbox().post(bad_id ? UINT64_MAX : request_id(host.pending.front().first), Signature{{}});
        CHECK_THROWS_CODE(building.step(), ErrorCode::InvalidArgument);
        CHECK_THROWS_CODE(building.step(), ErrorCode::InvalidArgument);
        CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
        host.deliver();
    }
    ManualBuildHost host;
    Building premature(BuildSession(signing_settings()), host);
    CHECK_THROWS_CODE(std::move(premature).finish(), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(premature.step(), ErrorCode::InvalidArgument);
}

class InlineBuildHost : public AsyncBuildHost {
public:
    MemoryBuildHost backing{fixture_bytes(), fixture_sign};
    Building *operation = nullptr;
    int failure = 0;
    void start(BuildRequest request, BuildCompletion done) override {
        if (failure == 1) throw std::runtime_error("start failed");
        if (failure == 2) throw 42;
        if (operation) CHECK_THROWS_CODE(operation->step(), ErrorCode::InvalidArgument);
        done(answer(backing, request));
        done(Failed{"duplicate ignored"});
        throw std::runtime_error("completion already won");
    }
};

TEST(inline_build_callbacks_do_not_recurse_and_finish_is_consumed) {
    InlineBuildHost host;
    Building building(BuildSession(signing_settings()), host);
    host.operation = &building;
    while (!building.step()) building.mailbox().wait();
    const auto count = building.started();
    CHECK(building.step());
    CHECK_EQ(building.started(), count);
    CHECK_EQ(building.in_flight(), size_t{0});
    CHECK(!std::move(building).finish().manifest.empty());
    CHECK_THROWS_CODE(building.step(), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    CHECK(trusted_signing_json(host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(build_futures_own_progress_and_deliver_standard_and_nonstandard_start_errors) {
    for (int failure : {0, 1, 2}) {
        auto host = std::make_shared<InlineBuildHost>();
        host->failure = failure;
        auto future = build_future(BuildSession(signing_settings()), host);
        if (failure) CHECK_THROWS_CODE(future.get(), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
        else CHECK(!future.get().manifest.empty());
    }
    CHECK_THROWS_CODE(build_future(BuildSession(signing_settings()), nullptr), ErrorCode::InvalidArgument);
}

TEST(pooled_build_submission_failure_and_throwing_completion_do_not_escape_workers) {
    struct RejectingPool : ThreadPool {
        void post(std::function<void()>) override { throw std::runtime_error("pool rejected task"); }
    } rejected;
    MemoryBuildHost backing(fixture_bytes(), fixture_sign);
    PooledBuildHost refused(backing, rejected);
    CHECK_THROWS_CODE(build_parallel(BuildSession(signing_settings()), refused),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    CHECK_THROWS_CODE(PooledBuildHost(std::shared_ptr<SyncBuildHost>{}, rejected), ErrorCode::InvalidArgument);
    auto pool = make_simple_thread_pool(2);
    PooledBuildHost accepted(backing, *pool);
    std::promise<BuildReply> result;
    auto future = result.get_future();
    accepted.start(BuildLengthRequest{1, BuildStream::Source}, [&](BuildReply reply) {
        result.set_value(std::move(reply));
        throw std::runtime_error("completion refused");
    });
    const auto reply = future.get();
    pool.reset();
    CHECK_EQ(std::get<Length>(reply).value, backing.length(BuildStream::Source));
}

TEST(pooled_build_failures_release_the_host_for_later_requests) {
    struct FailingHost : MemoryBuildHost {
        FailingHost() : MemoryBuildHost({1, 2, 3}) {}
        uint64_t length(BuildStream stream) override {
            if (stream == BuildStream::Source) throw std::runtime_error("length refused");
            throw 42;
        }
    } host;
    auto pool = make_simple_thread_pool(1);
    PooledBuildHost adapter(host, *pool);
    for (auto stream : {BuildStream::Source, BuildStream::Output}) {
        std::promise<BuildReply> result;
        auto future = result.get_future();
        adapter.start(BuildLengthRequest{1, stream}, [&](BuildReply reply) {
            result.set_value(std::move(reply));
        });
        const auto reply = future.get();
        CHECK(std::holds_alternative<Failed>(reply));
        CHECK_EQ(std::get<Failed>(reply).message,
                 stream == BuildStream::Source ? "length refused" : "unknown build host error");
    }
    std::promise<BuildReply> result;
    auto future = result.get_future();
    adapter.start(WriteRequest{2, BuildStream::Output, 0, {9}}, [&](BuildReply reply) {
        result.set_value(std::move(reply));
    });
    CHECK(std::holds_alternative<Written>(future.get()));
    pool.reset();
    CHECK_EQ(host.output(), (std::vector<uint8_t>{9}));
}

TEST(pooled_builds_round_trip_memory_and_seekable_streams) {
    auto pool = make_simple_thread_pool(4);
    auto memory = std::make_shared<MemoryBuildHost>(fixture_bytes(), fixture_sign);
    auto pooled = std::make_shared<PooledBuildHost>(memory, *pool);
    CHECK(!build_future(BuildSession(signing_settings()), pooled).get().manifest.empty());
    CHECK(trusted_signing_json(memory->output()).find("Trusted") != std::string::npos);
    const auto source_bytes = fixture_bytes();
    std::istringstream source(std::string(source_bytes.begin(), source_bytes.end()));
    std::stringstream output;
    IOStreamBuildHost streams(source, output, fixture_sign);
    PooledBuildHost stream_pool(streams, *pool);
    CHECK(!build_parallel(BuildSession(signing_settings()), stream_pool).manifest.empty());
    const auto bytes = output.str();
    CHECK(trusted_signing_json({bytes.begin(), bytes.end()}).find("Trusted") != std::string::npos);
}

TEST(pooled_build_host_serializes_competing_writes_to_mutable_output) {
    struct ControlledHost : MemoryBuildHost {
        ControlledHost() : MemoryBuildHost({}) {}
        std::mutex mutex;
        std::condition_variable ready;
        bool entered = false, released = false;
        std::atomic<int> active{0};
        std::atomic<bool> overlapped{false};
        void write(BuildStream stream, uint64_t offset, const std::vector<uint8_t> &bytes) override {
            if (active.fetch_add(1) != 0) overlapped.store(true);
            {
                std::unique_lock<std::mutex> lock(mutex);
                if (!entered) {
                    entered = true;
                    ready.notify_all();
                    ready.wait(lock, [&] { return released; });
                }
            }
            MemoryBuildHost::write(stream, offset, bytes);
            active.fetch_sub(1);
        }
    } host;
    auto pool = make_simple_thread_pool(4);
    PooledBuildHost adapter(host, *pool);
    size_t finished = 0, written = 0;
    auto complete = [&](BuildReply reply) {
        std::lock_guard<std::mutex> lock(host.mutex);
        if (std::holds_alternative<Written>(reply)) ++written;
        ++finished;
        host.ready.notify_all();
    };
    adapter.start(WriteRequest{1, BuildStream::Output, 0, {0}}, complete);
    {
        std::unique_lock<std::mutex> lock(host.mutex);
        host.ready.wait(lock, [&] { return host.entered; });
    }
    for (uint64_t index = 1; index < 8; ++index)
        adapter.start(WriteRequest{index + 1, BuildStream::Output, index, {static_cast<uint8_t>(index)}}, complete);
    {
        std::unique_lock<std::mutex> lock(host.mutex);
        host.released = true;
        host.ready.notify_all();
        host.ready.wait(lock, [&] { return finished == 8; });
    }
    pool.reset();
    CHECK_EQ(written, size_t{8});
    CHECK(!host.overlapped.load());
    CHECK_EQ(host.active.load(), 0);
    CHECK_EQ(host.output(), (std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7}));
}

TEST(pooled_adapter_and_operation_can_die_while_owned_host_work_is_in_flight) {
    std::mutex mutex;
    std::condition_variable ready;
    bool entered = false, released = false, signalled = false;
    auto pool = make_simple_thread_pool(2);
    auto host = std::make_shared<MemoryBuildHost>(fixture_bytes(), [&](const auto &algorithm, const auto &data) {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        ready.notify_all();
        ready.wait(lock, [&] { return released; });
        return fixture_sign(algorithm, data);
    });
    std::weak_ptr<SyncBuildHost> retained = host;
    auto adapter = std::make_unique<PooledBuildHost>(host, *pool);
    auto operation = std::make_unique<Building>(BuildSession(signing_settings()), *adapter);
    while (!operation->step()) {
        if (!operation->mailbox().set_waker([&] {
            std::lock_guard<std::mutex> lock(mutex);
            signalled = true;
            ready.notify_all();
        })) continue;
        std::unique_lock<std::mutex> lock(mutex);
        ready.wait(lock, [&] { return entered || signalled; });
        signalled = false;
        if (entered) break;
    }
    operation.reset();
    adapter.reset();
    host.reset();
    CHECK(!retained.expired());
    { std::lock_guard<std::mutex> lock(mutex); released = true; }
    ready.notify_all();
    pool.reset();
    CHECK(retained.expired());
}

TEST(blocking_signing_round_trips_trusted_with_owned_report) {
    auto settings = signing_settings();
    BuildSession session(settings);
    settings.definition_json.clear();
    settings.certificates.clear();
    MemoryBuildHost host(fixture_bytes(), fixture_sign);
    auto report = build_and_sign(std::move(session), host);
    const auto json = trusted_signing_json(host.output());
    CHECK(json.find("Trusted") != std::string::npos);
    CHECK(json.find("baseline.jpg") != std::string::npos);
    CHECK(json.find("c2pa.actions.v2") != std::string::npos);
    CHECK(!report.manifest.empty());
    CHECK(!report.exclusions.empty());
    uint64_t previous = 0;
    for (const auto &range : report.exclusions) {
        CHECK(range.start >= previous);
        CHECK(range.start <= host.output().size());
        CHECK(range.len <= host.output().size() - range.start);
        previous = range.start;
    }
    const auto copied = report;
    report.manifest.clear();
    report.exclusions.clear();
    CHECK(!copied.manifest.empty());
    CHECK(!copied.exclusions.empty());
}

TEST(build_session_moves_consumes_and_preserves_owned_pending_values) {
    BuildSession original(signing_settings());
    const auto first = original.advance();
    CHECK(!first.done);
    CHECK(!first.requests.empty());
    CHECK(original.advance().requests.empty());
    CHECK(!original.advance().done);
    BuildSession moved(std::move(original));
    CHECK_THROWS_CODE(original.advance(), ErrorCode::InvalidArgument);
    BuildSession assigned(signing_settings());
    assigned = std::move(moved);
    CHECK_THROWS_CODE(moved.fulfill(0, Failed{"moved"}), ErrorCode::InvalidArgument);
    const auto id = request_id(first.requests.front());
    CHECK_THROWS_CODE(assigned.fulfill(id, Signature{{}}), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(assigned.fulfill(UINT64_MAX, Length{0}), ErrorCode::InvalidArgument);
    MemoryBuildHost host(fixture_bytes(), fixture_sign);
    for (const auto &pending : first.requests) assigned.fulfill(request_id(pending), answer(host, pending));
    CHECK_THROWS_CODE(assigned.fulfill(id, Length{0}), ErrorCode::InvalidArgument);
    std::vector<BuildRequest> retained;
    for (;;) {
        const auto step = assigned.advance();
        if (step.done) break;
        CHECK(!step.requests.empty());
        if (step.requests.empty()) throw std::runtime_error("unexpected stalled build");
        for (const auto &pending : step.requests) {
            retained.push_back(pending);
            assigned.fulfill(request_id(pending), answer(host, pending));
        }
    }
    const auto report = std::move(assigned).finish();
    CHECK(!report.manifest.empty());
    CHECK_THROWS_CODE(assigned.advance(), ErrorCode::InvalidArgument);
    bool saw_sign = false;
    bool saw_write = false;
    for (const auto &pending : retained) {
        if (const auto *sign = std::get_if<SignRequest>(&pending)) {
            CHECK_EQ(sign->algorithm, "es256");
            CHECK(!sign->data.empty());
            saw_sign = true;
        }
        if (const auto *write = std::get_if<WriteRequest>(&pending)) {
            CHECK(!write->bytes.empty());
            saw_write = true;
        }
    }
    CHECK(saw_sign && saw_write);
}

TEST(premature_finish_consumes_build_and_moved_from_finish_is_safe) {
    BuildSession session(signing_settings());
    CHECK_THROWS_CODE(std::move(session).finish(), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(std::move(session).finish(), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(session.advance(), ErrorCode::InvalidArgument);
}

TEST(memory_build_host_keeps_streams_distinct_and_checks_bounds) {
    MemoryBuildHost host({1, 2, 3});
    CHECK_EQ(host.length(BuildStream::Source), uint64_t(3));
    CHECK_EQ(host.length(BuildStream::Output), uint64_t(0));
    host.write(BuildStream::Output, 1, {9, 8});
    CHECK_EQ(host.read(BuildStream::Source, 1, 2), (std::vector<uint8_t>{2, 3}));
    CHECK_EQ(host.read(BuildStream::Output, 0, 3), (std::vector<uint8_t>{0, 9, 8}));
    CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{1, BuildStream::Source, 2, 2})));
    CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{1, BuildStream::Output, UINT64_MAX, 1})));
    CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{1, BuildStream::Output, UINT64_MAX, {1}})));
    CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{1, BuildStream::Source, 0, {1}})));
    CHECK(std::holds_alternative<Written>(answer(host, WriteRequest{1, BuildStream::Output, 0, {1}})));
    CHECK_EQ(std::get<Length>(answer(host, BuildLengthRequest{1, BuildStream::Output})).value, uint64_t(3));
}

TEST(build_request_conversion_rejects_unknown_abi_values) {
    bool rejected = false;
    try { detail::build_stream(99); } catch (const std::runtime_error &) { rejected = true; }
    CHECK(rejected);
    C2paSmBuildRequest pending{};
    pending.kind = 99;
    rejected = false;
    try { detail::describe(pending); } catch (const std::runtime_error &) { rejected = true; }
    CHECK(rejected);
}

TEST(build_request_conversion_accepts_empty_buffers_without_dereferencing_them) {
    CHECK(detail::build_bytes({nullptr, 0}).empty());
    CHECK(detail::build_string({nullptr, 0}).empty());
    C2paSmBuildRequest pending{};
    pending.id = 42;
    pending.kind = C2PA_SM_BUILD_REQUEST_SIGN;
    const auto sign = std::get<SignRequest>(detail::describe(pending));
    CHECK_EQ(sign.id, uint64_t(42));
    CHECK(sign.algorithm.empty());
    CHECK(sign.data.empty());
    pending.kind = C2PA_SM_BUILD_REQUEST_TIMESTAMP;
    const auto timestamp = std::get<TimestampRequest>(detail::describe(pending));
    CHECK_EQ(timestamp.id, uint64_t(42));
    CHECK(timestamp.url.empty());
    CHECK(timestamp.body.empty());
    pending.kind = C2PA_SM_BUILD_REQUEST_WRITE;
    pending.stream = C2PA_SM_BUILD_OUTPUT;
    const auto write = std::get<WriteRequest>(detail::describe(pending));
    CHECK_EQ(write.id, uint64_t(42));
    CHECK(write.stream == BuildStream::Output);
    CHECK(write.bytes.empty());
}

TEST(build_request_conversion_copies_nonempty_payloads_without_terminators) {
    std::vector<uint8_t> bytes{1, 0, 3};
    std::string text = "es256";
    C2paSmBuildRequest pending{};
    pending.id = 42;
    pending.data = {bytes.data(), bytes.size()};
    pending.algorithm = {reinterpret_cast<const uint8_t *>(text.data()), text.size()};
    pending.url = pending.algorithm;
    pending.kind = C2PA_SM_BUILD_REQUEST_SIGN;
    const auto sign = std::get<SignRequest>(detail::describe(pending));
    pending.kind = C2PA_SM_BUILD_REQUEST_TIMESTAMP;
    const auto timestamp = std::get<TimestampRequest>(detail::describe(pending));
    bytes.assign(bytes.size(), 0);
    text.assign(text.size(), 'x');
    CHECK_EQ(sign.algorithm, "es256");
    CHECK_EQ(sign.data, (std::vector<uint8_t>{1, 0, 3}));
    CHECK_EQ(timestamp.url, "es256");
    CHECK_EQ(timestamp.body, sign.data);
}

TEST(build_hosts_accept_empty_io_at_eof_without_changing_output) {
    MemoryBuildHost memory({1, 2, 3});
    std::istringstream source("abc");
    std::stringstream output;
    IOStreamBuildHost streams(source, output);
    for (SyncBuildHost *host : {static_cast<SyncBuildHost *>(&memory), static_cast<SyncBuildHost *>(&streams)}) {
        CHECK(std::get<Bytes>(answer(*host, BuildReadRequest{1, BuildStream::Source, 3, 0})).data.empty());
        CHECK(std::get<Bytes>(answer(*host, BuildReadRequest{2, BuildStream::Output, 0, 0})).data.empty());
        CHECK(std::holds_alternative<Written>(answer(*host, WriteRequest{3, BuildStream::Output, 0, {}})));
        CHECK_EQ(host->length(BuildStream::Output), uint64_t(0));
        CHECK(std::holds_alternative<Failed>(answer(*host, BuildReadRequest{4, BuildStream::Source, 4, 0})));
    }
    CHECK(memory.output().empty());
    CHECK(output.str().empty());
}

TEST(blocking_signing_supports_seekable_iostreams) {
    const auto source = fixture_bytes();
    std::istringstream input(std::string(source.begin(), source.end()));
    std::stringstream output;
    IOStreamBuildHost host(input, output, fixture_sign);
    const auto report = build_and_sign(BuildSession(signing_settings()), host);
    CHECK(!report.manifest.empty());
    const auto bytes = output.str();
    CHECK(trusted_signing_json({bytes.begin(), bytes.end()}).find("Trusted") != std::string::npos);
}

TEST(stream_host_rejects_alias_nonempty_failed_and_short_io) {
    std::stringstream input("abc");
    std::stringstream output;
    bool rejected = false;
    try { IOStreamBuildHost host(input, input); } catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
    rejected = false;
    try { IOStreamBuildHost host(output, input); } catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
    IOStreamBuildHost host(input, output);
    CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{1, BuildStream::Source, 2, 2})));
    CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{1, BuildStream::Source, 0, {1}})));
    output.setstate(std::ios::badbit);
    CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{1, BuildStream::Output, 0, {1}})));
    CHECK(std::holds_alternative<Failed>(answer(host, BuildLengthRequest{1, BuildStream::Output})));
    input.exceptions(std::ios::badbit);
    try { input.setstate(std::ios::badbit); } catch (const std::exception &) {}
    CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{1, BuildStream::Source, 0, 1})));
}

TEST(stream_host_detects_short_reads_short_writes_flush_and_seek_failures) {
    struct ShortRead : std::stringbuf {
        ShortRead() : std::stringbuf("abc") {}
        std::streamsize xsgetn(char *destination, std::streamsize count) override {
            return std::stringbuf::xsgetn(destination, count > 0 ? count - 1 : 0);
        }
    } short_read;
    struct ShortWrite : std::stringbuf {
        std::streamsize xsputn(const char *, std::streamsize count) override {
            return count > 0 ? count - 1 : 0;
        }
    } short_write;
    struct FailedFlush : std::stringbuf {
        int sync() override { return -1; }
    } failed_flush;
    std::istream source(&short_read);
    std::stringstream output;
    IOStreamBuildHost reader(source, output);
    CHECK(std::holds_alternative<Failed>(answer(reader, BuildReadRequest{1, BuildStream::Source, 0, 3})));
    std::istringstream input("abc");
    std::iostream short_output(&short_write);
    IOStreamBuildHost writer(input, short_output);
    CHECK(std::holds_alternative<Failed>(answer(writer, WriteRequest{1, BuildStream::Output, 0, {1, 2, 3}})));
    std::iostream unflushed(&failed_flush);
    IOStreamBuildHost flushing(input, unflushed);
    CHECK(std::holds_alternative<Failed>(answer(flushing, WriteRequest{1, BuildStream::Output, 0, {1}})));
    CHECK(std::holds_alternative<Failed>(answer(reader, WriteRequest{1, BuildStream::Output, UINT64_MAX, {1}})));
    struct Unseekable : std::streambuf {} unseekable;
    std::iostream invalid(&unseekable);
    bool rejected = false;
    try { IOStreamBuildHost host(input, invalid); } catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
}

TEST(stream_host_converts_exceptions_from_each_io_operation_into_failures) {
    struct ThrowingBuffer : std::stringbuf {
        enum class Operation { None, Seek, SeekPosition, Tell, Read, Write, Flush };
        explicit ThrowingBuffer(const std::string &contents = {}) : std::stringbuf(contents) {}
        Operation operation = Operation::None;
        pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                         std::ios_base::openmode mode) override {
            if (operation == Operation::Seek) throw std::runtime_error("seek refused");
            if (operation == Operation::Tell && direction == std::ios::cur)
                throw std::runtime_error("position refused");
            return std::stringbuf::seekoff(offset, direction, mode);
        }
        pos_type seekpos(pos_type position, std::ios_base::openmode mode) override {
            if (operation == Operation::Seek || operation == Operation::SeekPosition)
                throw std::runtime_error("seek refused");
            return std::stringbuf::seekpos(position, mode);
        }
        std::streamsize xsgetn(char *destination, std::streamsize count) override {
            if (operation == Operation::Read) throw std::runtime_error("read refused");
            return std::stringbuf::xsgetn(destination, count);
        }
        std::streamsize xsputn(const char *source, std::streamsize count) override {
            if (operation == Operation::Write) throw std::runtime_error("write refused");
            return std::stringbuf::xsputn(source, count);
        }
        int sync() override {
            if (operation == Operation::Flush) throw std::runtime_error("flush refused");
            return std::stringbuf::sync();
        }
    };
    for (auto operation : {ThrowingBuffer::Operation::Seek, ThrowingBuffer::Operation::SeekPosition,
                           ThrowingBuffer::Operation::Tell, ThrowingBuffer::Operation::Read,
                           ThrowingBuffer::Operation::Write, ThrowingBuffer::Operation::Flush}) {
        ThrowingBuffer source_buffer("abc");
        ThrowingBuffer output_buffer;
        std::istream source(&source_buffer);
        std::iostream output(&output_buffer);
        source.exceptions(std::ios::badbit | std::ios::failbit);
        output.exceptions(std::ios::badbit | std::ios::failbit);
        IOStreamBuildHost host(source, output);
        if (operation != ThrowingBuffer::Operation::Write && operation != ThrowingBuffer::Operation::Flush) {
            source_buffer.operation = operation;
            CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{1, BuildStream::Source, 0, 1})));
        }
        if (operation != ThrowingBuffer::Operation::Read && operation != ThrowingBuffer::Operation::Tell) {
            output_buffer.operation = operation;
            CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{2, BuildStream::Output, 0, {1}})));
        }
    }
}

TEST(stream_host_rejects_an_unavailable_current_position_after_a_successful_seek) {
    struct MissingPosition : std::stringbuf {
        MissingPosition() : std::stringbuf("abc") {}
        pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                         std::ios_base::openmode mode) override {
            if (direction == std::ios::cur) return pos_type(off_type(-1));
            return std::stringbuf::seekoff(offset, direction, mode);
        }
    } buffer;
    std::istream source(&buffer);
    std::stringstream output;
    IOStreamBuildHost host(source, output);
    CHECK(std::holds_alternative<Failed>(answer(host, BuildLengthRequest{1, BuildStream::Source})));
    CHECK(source.good());
}

TEST(missing_throwing_and_invalid_signers_fail_the_build) {
    const std::vector<BuildSigner> signers{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("signer refused"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1}; },
    };
    for (const auto &signer : signers) {
        MemoryBuildHost host(fixture_bytes(), signer);
        CHECK_THROWS_CODE(build_and_sign(BuildSession(signing_settings()), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
}

TEST(timestamp_callback_receives_url_and_der_and_failures_fail_closed) {
    std::vector<BuildTimestamp> callbacks{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("offline"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1, 2}; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{0x30, 5, 0x30, 3, 2, 1, 2}; },
    };
    for (const auto &callback : callbacks) {
        MemoryBuildHost host(fixture_bytes(), fixture_sign, callback);
        CHECK_THROWS_CODE(build_and_sign(BuildSession(signing_settings(true)), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
    bool called = false;
    MemoryBuildHost host(fixture_bytes(), fixture_sign, [&](const auto &url, const auto &body) {
        CHECK_EQ(url, "https://tsa.example/");
        CHECK(!body.empty() && body.front() == 0x30);
        called = true;
        return std::vector<uint8_t>{0x30, 8, 0x30, 3, 2, 1, 0, 0x30, 1, 0};
    });
    const auto report = build_and_sign(BuildSession(signing_settings(true)), host);
    CHECK(called);
    CHECK(!report.manifest.empty());
}

TEST(short_reads_and_host_failures_fail_without_spinning) {
    struct Broken : MemoryBuildHost {
        explicit Broken(int failure) : MemoryBuildHost(fixture_bytes(), fixture_sign), failure_(failure) {}
        std::vector<uint8_t> read(BuildStream stream, uint64_t start, uint64_t len) override {
            if (failure_ == 0) return {};
            return MemoryBuildHost::read(stream, start, len);
        }
        uint64_t length(BuildStream stream) override {
            if (failure_ == 1) throw std::runtime_error("length failed");
            return MemoryBuildHost::length(stream);
        }
        void write(BuildStream stream, uint64_t offset, const std::vector<uint8_t> &bytes) override {
            if (failure_ == 2) throw 42;
            MemoryBuildHost::write(stream, offset, bytes);
        }
        int failure_;
    };
    for (int failure = 0; failure < 3; ++failure) {
        Broken host(failure);
        CHECK_THROWS_CODE(build_and_sign(BuildSession(signing_settings()), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
}

#if defined(__unix__) || defined(__APPLE__)
TEST(file_build_read_reports_source_truncation_after_length_check) {
    std::string pattern = (std::filesystem::temp_directory_path() / "c2pa-truncate-test-XXXXXX").string();
    if (!::mkdtemp(pattern.data())) throw std::runtime_error("cannot create test directory");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); }
    } cleanup{pattern};
    const auto source = cleanup.path / "source.jpg";
    { std::ofstream input(source, std::ios::binary); input << "abc"; }
    struct TruncatingHost : FileBuildHost {
        std::filesystem::path source;
        TruncatingHost(const std::filesystem::path &input, const std::filesystem::path &output)
            : FileBuildHost(input, output), source(input) {}
        uint64_t length(BuildStream stream) override {
            const auto size = FileBuildHost::length(stream);
            if (stream == BuildStream::Source) std::filesystem::resize_file(source, 0);
            return size;
        }
    };
    {
        TruncatingHost host(source, cleanup.path / "output.jpg");
        const auto reply = answer(host, BuildReadRequest{1, BuildStream::Source, 0, 3});
        CHECK(std::holds_alternative<Failed>(reply));
        CHECK_EQ(std::get<Failed>(reply).message, "build file read failed");
    }
    CHECK_EQ(std::filesystem::file_size(source), uintmax_t{0});
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                           std::filesystem::directory_iterator{}), 1);
}

TEST(file_signing_publishes_only_success_and_cleans_temporaries) {
    std::string pattern = (std::filesystem::temp_directory_path() / "c2pa-sign-test-XXXXXX").string();
    if (!::mkdtemp(pattern.data())) throw std::runtime_error("cannot create test directory");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); }
    } cleanup{pattern};
    const auto destination = cleanup.path / "signed.jpg";
    const auto settings = signing_settings();
    {
        struct FileSizeLimit {
            struct rlimit previous_limit{};
            struct sigaction previous_action{};
            explicit FileSizeLimit(rlim_t maximum) {
                if (::getrlimit(RLIMIT_FSIZE, &previous_limit) != 0)
                    throw std::runtime_error("cannot inspect file-size limit");
                struct sigaction ignored{};
                ignored.sa_handler = SIG_IGN;
                sigemptyset(&ignored.sa_mask);
                if (::sigaction(SIGXFSZ, &ignored, &previous_action) != 0)
                    throw std::runtime_error("cannot ignore file-size signal");
                auto limited = previous_limit;
                limited.rlim_cur = maximum;
                if (::setrlimit(RLIMIT_FSIZE, &limited) != 0) {
                    ::sigaction(SIGXFSZ, &previous_action, nullptr);
                    throw std::runtime_error("cannot limit file size");
                }
            }
            ~FileSizeLimit() {
                ::setrlimit(RLIMIT_FSIZE, &previous_limit);
                ::sigaction(SIGXFSZ, &previous_action, nullptr);
            }
            FileSizeLimit(const FileSizeLimit &) = delete;
            FileSizeLimit &operator=(const FileSizeLimit &) = delete;
        };
        FileBuildHost host(C2PA_SM_FIXTURE, destination);
        struct rlimit initial_limit{};
        struct sigaction initial_action{};
        CHECK_EQ(::getrlimit(RLIMIT_FSIZE, &initial_limit), 0);
        CHECK_EQ(::sigaction(SIGXFSZ, nullptr, &initial_action), 0);
        const auto reply = [&host] {
            FileSizeLimit limit(3);
            return answer(host, WriteRequest{1, BuildStream::Output, 0, {1, 2, 3, 4, 5}});
        }();
        struct rlimit restored_limit{};
        struct sigaction restored_action{};
        CHECK_EQ(::getrlimit(RLIMIT_FSIZE, &restored_limit), 0);
        CHECK_EQ(::sigaction(SIGXFSZ, nullptr, &restored_action), 0);
        CHECK_EQ(restored_limit.rlim_cur, initial_limit.rlim_cur);
        CHECK_EQ(restored_limit.rlim_max, initial_limit.rlim_max);
        CHECK(restored_action.sa_handler == initial_action.sa_handler);
        CHECK(std::holds_alternative<Failed>(reply));
        CHECK_EQ(std::get<Failed>(reply).message, "build file write failed");
        CHECK_EQ(host.length(BuildStream::Output), uint64_t(3));
        CHECK_EQ(host.read(BuildStream::Output, 0, 3), (std::vector<uint8_t>{1, 2, 3}));
    }
    CHECK(std::filesystem::is_empty(cleanup.path));
    {
        FileBuildHost host(C2PA_SM_FIXTURE, destination);
        const auto source_length = host.length(BuildStream::Source);
        CHECK(source_length > 0);
        CHECK(std::get<Bytes>(answer(host, BuildReadRequest{1, BuildStream::Source, source_length, 0})).data.empty());
        CHECK(std::get<Bytes>(answer(host, BuildReadRequest{2, BuildStream::Output, 0, 0})).data.empty());
        CHECK(std::holds_alternative<Written>(answer(host, WriteRequest{3, BuildStream::Output, 0, {}})));
        CHECK_EQ(host.length(BuildStream::Output), uint64_t(0));
        CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{4, BuildStream::Source, source_length, 1})));
        CHECK(std::holds_alternative<Failed>(answer(host, BuildReadRequest{5, BuildStream::Output, UINT64_MAX, 1})));
        CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{6, BuildStream::Source, 0, {1}})));
        CHECK(std::holds_alternative<Failed>(answer(host, WriteRequest{7, BuildStream::Output, UINT64_MAX, {1}})));
        CHECK_EQ(host.length(BuildStream::Source), source_length);
        CHECK_EQ(host.length(BuildStream::Output), uint64_t(0));
    }
    CHECK(std::filesystem::is_empty(cleanup.path));
    {
        std::ofstream output(destination);
        output << "keep me";
    }
    CHECK_THROWS_CODE(build_and_sign_file(BuildSettings{}, C2PA_SM_FIXTURE, destination, fixture_sign),
                      ErrorCode::InvalidArgument);
    {
        std::ifstream input(destination);
        CHECK_EQ(std::string(std::istreambuf_iterator<char>(input), {}), "keep me");
    }
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                           std::filesystem::directory_iterator{}), 1);
    CHECK_THROWS_CODE(build_and_sign_file(settings, C2PA_SM_FIXTURE, destination, {}), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    {
        std::ifstream input(destination);
        CHECK_EQ(std::string(std::istreambuf_iterator<char>(input), {}), "keep me");
    }
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 1);
    const std::vector<BuildTimestamp> timestamp_failures{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("offline"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1, 2}; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{0x30, 5, 0x30, 3, 2, 1, 2}; },
    };
    const auto absent = cleanup.path / "not-published.jpg";
    for (const auto &timestamp : timestamp_failures) {
        for (const auto &output_path : {destination, absent}) {
            CHECK_THROWS_CODE(build_and_sign_file(signing_settings(true), C2PA_SM_FIXTURE, output_path,
                                                  fixture_sign, timestamp),
                              static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
            std::ifstream preserved(destination);
            CHECK_EQ(std::string(std::istreambuf_iterator<char>(preserved), {}), "keep me");
            CHECK(!std::filesystem::exists(absent));
            CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                                   std::filesystem::directory_iterator{}), 1);
        }
    }
    const auto report = build_and_sign_file(settings, C2PA_SM_FIXTURE, destination, fixture_sign);
    CHECK(!report.manifest.empty());
    std::ifstream input(destination, std::ios::binary);
    const std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(input), {});
    CHECK(trusted_signing_json(bytes).find("Trusted") != std::string::npos);
    const auto in_place = cleanup.path / "in-place.jpg";
    std::filesystem::copy_file(destination, in_place);
    CHECK_THROWS_CODE(build_and_sign_file(settings, in_place, in_place, {}),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    {
        std::ifstream preserved(in_place, std::ios::binary);
        CHECK_EQ(std::vector<uint8_t>(std::istreambuf_iterator<char>(preserved), {}), bytes);
    }
    CHECK(!build_and_sign_file(settings, in_place, in_place, fixture_sign).manifest.empty());
    {
        std::ifstream signed_input(in_place, std::ios::binary);
        const std::vector<uint8_t> signed_bytes(std::istreambuf_iterator<char>(signed_input), {});
        CHECK(trusted_signing_json(signed_bytes).find("Trusted") != std::string::npos);
    }
    std::filesystem::remove(in_place);
    const auto directory = cleanup.path / "cannot-replace";
    std::filesystem::create_directory(directory);
    bool rejected = false;
    try { build_and_sign_file(settings, C2PA_SM_FIXTURE, directory, fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
    CHECK(std::filesystem::is_directory(directory));
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 2);
    rejected = false;
    try { build_and_sign_file(settings, cleanup.path / "missing.jpg", destination, fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 2);
    const auto link = cleanup.path / "link.jpg";
    std::filesystem::create_symlink(destination, link);
    CHECK_THROWS_CODE(build_and_sign_file(settings, C2PA_SM_FIXTURE, link, {}), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    CHECK(std::filesystem::is_symlink(link));
    build_and_sign_file(settings, C2PA_SM_FIXTURE, link, fixture_sign);
    CHECK(!std::filesystem::is_symlink(link));
    std::ifstream unchanged(destination, std::ios::binary);
    CHECK_EQ(std::vector<uint8_t>(std::istreambuf_iterator<char>(unchanged), {}), bytes);
    rejected = false;
    try { build_and_sign_file(settings, C2PA_SM_FIXTURE, cleanup.path / "missing" / "out.jpg", fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    CHECK(rejected);
    for (bool invalid_source : {false, true}) {
        auto invalid = destination.string();
        invalid.push_back('\0');
        invalid += "suffix";
        rejected = false;
        try {
            build_and_sign_file(settings,
                invalid_source ? std::filesystem::path(invalid) : std::filesystem::path(C2PA_SM_FIXTURE),
                invalid_source ? destination : std::filesystem::path(invalid), fixture_sign);
        } catch (const std::exception &) { rejected = true; }
        CHECK(rejected);
    }
    CHECK_THROWS_CODE(build_and_sign_file(settings, cleanup.path, destination, fixture_sign),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    CHECK_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 3);
}
#endif

TEST(signing_abi_values_are_grouped_enums_with_stable_integer_values) {
    static_assert(std::is_enum_v<C2paSmBuildErrorCode>);
    static_assert(std::is_enum_v<C2paSmBuildRequestKind>);
    static_assert(std::is_enum_v<C2paSmBuildReplyKind>);
    static_assert(std::is_enum_v<C2paSmBuildStream>);
    static_assert(C2PA_SM_ERR_BUILD == 6);
    static_assert(C2PA_SM_BUILD_REQUEST_READ == 0 && C2PA_SM_BUILD_REQUEST_LENGTH == 1 &&
                  C2PA_SM_BUILD_REQUEST_WRITE == 2 && C2PA_SM_BUILD_REQUEST_SIGN == 3 &&
                  C2PA_SM_BUILD_REQUEST_TIMESTAMP == 4);
    static_assert(C2PA_SM_BUILD_REPLY_BYTES == 0 && C2PA_SM_BUILD_REPLY_LENGTH == 1 &&
                  C2PA_SM_BUILD_REPLY_WRITTEN == 2 && C2PA_SM_BUILD_REPLY_SIGNATURE == 3 &&
                  C2PA_SM_BUILD_REPLY_TIMESTAMP == 4 && C2PA_SM_BUILD_REPLY_FAILED == 5);
    static_assert(C2PA_SM_BUILD_SOURCE == 0 && C2PA_SM_BUILD_OUTPUT == 1);
    static_assert(std::is_same_v<decltype(C2paSmBuildReply{}.kind), int>);
    C2paSmBuildReply reply{};
    reply.kind = C2PA_SM_BUILD_REPLY_SIGNATURE;
    CHECK_EQ(reply.kind, 3);
}

TEST(the_generated_signing_abi_links_and_returns_owned_errors) {
    C2paSmBuildSession *session = nullptr;
    C2paSmError *error = nullptr;
    const int code = c2pa_sm_build_session_new("{}", "image/jpeg", "es256", nullptr, 0,
                                              &session, &error);
    CHECK_EQ(code, C2PA_SM_ERR_INVALID_ARGUMENT);
    CHECK(session == nullptr);
    CHECK(error != nullptr);
    CHECK_EQ(c2pa_sm_error_code(error), code);
    CHECK(std::string(c2pa_sm_error_message(error)).size() > 0);
    c2pa_sm_error_free(error);
    CHECK_EQ(c2pa_sm_build_session_free(nullptr, nullptr), C2PA_SM_OK);
    CHECK_EQ(c2pa_sm_sign_report_free(nullptr, nullptr), C2PA_SM_OK);
}

TEST(signing_settings_keep_certificates_and_definition_as_owned_values) {
    BuildSettings settings;
    CHECK_EQ(settings.format, "image/jpeg");
    CHECK_EQ(settings.algorithm, "es256");
    CHECK(settings.certificates.empty());
    settings.definition_json = "{}";
    settings.certificates = {{1, 2}, {3, 4}};
    auto copied = settings;
    settings.definition_json.clear();
    settings.certificates.front().clear();
    CHECK_EQ(copied.definition_json, "{}");
    CHECK_EQ(copied.certificates.front(), (std::vector<uint8_t>{1, 2}));
    CHECK_EQ(copied.certificates.back(), (std::vector<uint8_t>{3, 4}));
}

TEST(signing_requests_identify_streams_and_own_their_payloads) {
    static_assert(std::variant_size_v<BuildRequest> == 5);
    std::vector<BuildRequest> requests{
        BuildReadRequest{10, BuildStream::Source, 20, 30},
        BuildLengthRequest{11, BuildStream::Source},
        WriteRequest{12, BuildStream::Output, 40, {1, 2}},
        SignRequest{13, "es256", {3, 4}},
        TimestampRequest{14, "https://tsa.example", {5, 6}},
        BuildReadRequest{15, BuildStream::Output, 50, 60},
        BuildLengthRequest{16, BuildStream::Output},
    };
    uint64_t expected_id = 10;
    for (const auto &request : requests) {
        CHECK_EQ(std::visit([](const auto &pending) { return pending.id; }, request), expected_id);
        ++expected_id;
    }
    const auto copied = requests;
    std::get<WriteRequest>(requests[2]).bytes.clear();
    std::get<SignRequest>(requests[3]).data.clear();
    std::get<TimestampRequest>(requests[4]).body.clear();
    CHECK(std::get<BuildReadRequest>(copied[0]).stream == BuildStream::Source);
    CHECK_EQ(std::get<BuildReadRequest>(copied[0]).start, uint64_t(20));
    CHECK_EQ(std::get<BuildReadRequest>(copied[0]).len, uint64_t(30));
    CHECK(std::get<BuildReadRequest>(copied[5]).stream == BuildStream::Output);
    CHECK(std::get<BuildLengthRequest>(copied[6]).stream == BuildStream::Output);
    CHECK(std::get<WriteRequest>(copied[2]).stream == BuildStream::Output);
    CHECK_EQ(std::get<WriteRequest>(copied[2]).offset, uint64_t(40));
    CHECK_EQ(std::get<WriteRequest>(copied[2]).bytes, (std::vector<uint8_t>{1, 2}));
    CHECK_EQ(std::get<SignRequest>(copied[3]).algorithm, "es256");
    CHECK_EQ(std::get<SignRequest>(copied[3]).data, (std::vector<uint8_t>{3, 4}));
    CHECK_EQ(std::get<TimestampRequest>(copied[4]).url, "https://tsa.example");
    CHECK_EQ(std::get<TimestampRequest>(copied[4]).body, (std::vector<uint8_t>{5, 6}));
}

TEST(signing_replies_and_report_hold_plain_values) {
    static_assert(std::variant_size_v<BuildReply> == 6);
    BuildReply reply = Bytes{{1, 2}};
    CHECK_EQ(std::get<Bytes>(reply).data.size(), size_t(2));
    reply = Length{42};
    CHECK_EQ(std::get<Length>(reply).value, uint64_t(42));
    reply = Written{};
    CHECK(std::holds_alternative<Written>(reply));
    reply = Signature{{3, 4}};
    CHECK_EQ(std::get<Signature>(reply).data, (std::vector<uint8_t>{3, 4}));
    reply = TimestampResponse{{5, 6}};
    CHECK_EQ(std::get<TimestampResponse>(reply).data, (std::vector<uint8_t>{5, 6}));
    reply = Failed{"signer unavailable"};
    CHECK_EQ(std::get<Failed>(reply).message, "signer unavailable");
    SignReport report{{7, 8}, {{10, 2}, {30, 4}}};
    auto copied = report;
    report.manifest.clear();
    report.exclusions.clear();
    CHECK_EQ(copied.manifest, (std::vector<uint8_t>{7, 8}));
    CHECK_EQ(copied.exclusions.size(), size_t(2));
    CHECK_EQ(copied.exclusions.front().start, uint64_t(10));
    CHECK_EQ(copied.exclusions.back().len, uint64_t(4));
}

TEST(a_signed_jpeg_reads_through_the_blocking_driver) {
    MemoryHost host = fixture_host();
    auto reader = read(Session("image/jpeg"), host);
    CHECK(reader.has_value());
    CHECK(reader->json().find("\"validation_state\": \"Valid\"") != std::string::npos);
    CHECK(reader->is_embedded());
    auto label = reader->active_label();
    CHECK(label.has_value());
    CHECK(reader->json().find(*label) != std::string::npos);
}

TEST(a_stream_and_a_file_read_the_same_as_memory) {
    MemoryHost memory = fixture_host();
    const std::string expected = json_of(read(Session("jpg"), memory));
    CHECK(!expected.empty());

    std::ifstream file(C2PA_SM_FIXTURE, std::ios::binary);
    IStreamHost stream(file);
    stream.read(0, 1);  // leave the stream mid-file: the host must seek
    CHECK_EQ(json_of(read(Session("image/jpeg"), stream)), expected);

    const std::vector<uint8_t> bytes = fixture_bytes();
    std::string raw(bytes.begin(), bytes.end());
    std::istringstream in(raw);
    IStreamHost from_string(in);
    CHECK_EQ(json_of(read(Session("image/jpeg"), from_string)), expected);

    // FileHost does not pin the clock, so only check that it reads at all
    // (the certificate chain's validity is a function of the wall clock).
    FileHost path_host(C2PA_SM_FIXTURE);
    CHECK_EQ(path_host.length(), fixture_bytes().size());
    CHECK_EQ(path_host.read(0, 2), (std::vector<uint8_t>{0xff, 0xd8}));
    CHECK(read(Session("image/jpeg"), path_host).has_value());
}

TEST(an_asset_with_no_manifest_store_is_nullopt_not_an_error) {
    MemoryHost host(std::vector<uint8_t>{0xff, 0xd8, 0xff, 0xd9});
    CHECK(!read(Session("image/jpeg"), host).has_value());
}

TEST(errors_are_values_with_a_code_and_a_name) {
    CHECK_THROWS_CODE(Session("image/png"), ErrorCode::UnsupportedType);
    try {
        Session session("image/png");
    } catch (const Exception &e) {
        CHECK_EQ(e.name(), "C2pa(UnsupportedType)");
        CHECK_EQ(std::string(e.what()), "type is unsupported");
    }
    CHECK_THROWS_CODE(Session("image/jpeg", std::string("{not json")), ErrorCode::InvalidArgument);
    Session ok("image/jpeg", std::string("{}"));  // valid settings are accepted
}

TEST(a_host_that_fails_a_read_fails_the_read_not_the_process) {
    struct Broken : MemoryHost {
        Broken() : MemoryHost(fixture_bytes(), kNow) {}
        std::vector<uint8_t> read(uint64_t, uint64_t) override { throw std::runtime_error("disk on fire"); }
    } host;
    CHECK_THROWS_CODE(read(Session("image/jpeg"), host), ErrorCode::Read);

    // A stream that is too short fails the same way.
    std::istringstream truncated(std::string(100, 'x'));
    IStreamHost short_stream(truncated);
    CHECK_THROWS_CODE(read(Session("image/jpeg"), short_stream), ErrorCode::Read);
    bool out_of_range = false;
    try {
        MemoryHost({1, 2, 3}).read(2, 5);
    } catch (const std::out_of_range &) {
        out_of_range = true;
    }
    CHECK(out_of_range);
}

TEST(a_stream_shorter_than_asked_is_a_host_failure) {
    std::istringstream in(std::string(10, 'x'));
    IStreamHost host(in);
    CHECK_EQ(host.length(), uint64_t(10));
    CHECK_EQ(host.read(5, 5).size(), size_t(5));
    bool threw = false;
    try {
        host.read(5, 50);
    } catch (const std::runtime_error &) {
        threw = true;
    }
    CHECK(threw);
}

TEST(a_stream_that_cannot_seek_has_no_length_rather_than_a_huge_one) {
    // A stream buffer that refuses every seek: tellg() then reports -1,
    // which must not become a length of 2^64 - 1.
    struct NoSeek : std::streambuf {
        pos_type seekoff(off_type, std::ios_base::seekdir, std::ios_base::openmode) override {
            return pos_type(off_type(-1));
        }
    } buffer;
    std::istream in(&buffer);
    IStreamHost host(in);
    bool threw = false;
    try {
        host.length();
    } catch (const std::runtime_error &) {
        threw = true;
    }
    CHECK(threw);
    // ...and a whole read against it fails as a host failure, not a hang.
    CHECK_THROWS_CODE(read(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(a_failed_clock_and_a_missing_file_are_host_failures_too) {
    struct NoClock : MemoryHost {
        NoClock() : MemoryHost(fixture_bytes()) {}
        int64_t now() override { throw std::runtime_error("no clock"); }
    } host;
    // The engine decides what a missing clock means; it must not crash.
    (void)read(Session("image/jpeg"), host);

    FileHost missing("/no/such/file.jpg");
    bool threw = false;
    try {
        missing.length();
    } catch (const std::runtime_error &) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        missing.read(0, 1);
    } catch (const std::runtime_error &) {
        threw = true;
    }
    CHECK(threw);
}

TEST(answer_turns_every_request_kind_into_a_reply_and_exceptions_into_failed) {
    MemoryHost host = fixture_host();
    CHECK(std::holds_alternative<Bytes>(answer(host, ReadRequest{1, 0, 4})));
    CHECK(std::holds_alternative<Length>(answer(host, LengthRequest{2})));
    CHECK_EQ(std::get<Time>(answer(host, TimeRequest{3})).seconds, kNow);
    // No network by default: a failure, which the engine treats as fail-open.
    auto ocsp = answer(host, OcspRequest{4, "http://ocsp.example/", {1, 2}});
    CHECK(std::holds_alternative<Failed>(ocsp));

    struct Responder : MemoryHost {
        Responder() : MemoryHost({}) {}
        std::vector<uint8_t> ocsp(const std::string &url, const std::vector<uint8_t> &body) override {
            return url == "http://ocsp.example/" ? body : std::vector<uint8_t>{};
        }
    } responder;
    auto answered = answer(responder, OcspRequest{5, "http://ocsp.example/", {7, 8}});
    CHECK_EQ(std::get<Ocsp>(answered).data, (std::vector<uint8_t>{7, 8}));

    // Even a thrown non-exception is a Failed, not a crash.
    struct Weird : MemoryHost {
        Weird() : MemoryHost({}) {}
        uint64_t length() override { throw 42; }
    } weird;
    CHECK(std::holds_alternative<Failed>(answer(weird, LengthRequest{6})));
}

TEST(every_kind_of_request_the_library_reports_is_described_as_plain_values) {
    // The engine never issues an OCSP request for this repository's
    // fixtures, so the description is checked on hand-built C structs.
    C2paSmRequest r{};
    r.id = 7;
    r.kind = C2PA_SM_REQUEST_READ;
    r.start = 5;
    r.len = 9;
    auto read_request = std::get<ReadRequest>(detail::describe(r));
    CHECK_EQ(read_request.id, uint64_t(7));
    CHECK_EQ(read_request.start, uint64_t(5));
    CHECK_EQ(read_request.len, uint64_t(9));

    r.kind = C2PA_SM_REQUEST_LENGTH;
    CHECK_EQ(std::get<LengthRequest>(detail::describe(r)).id, uint64_t(7));
    r.kind = C2PA_SM_REQUEST_TIME;
    CHECK_EQ(std::get<TimeRequest>(detail::describe(r)).id, uint64_t(7));

    const char url[] = "http://ocsp.example/";
    const uint8_t body[] = {1, 2, 3};
    r.kind = C2PA_SM_REQUEST_OCSP;
    r.url = url;
    r.url_len = sizeof(url) - 1;
    r.body = body;
    r.body_len = sizeof(body);
    auto ocsp = std::get<OcspRequest>(detail::describe(r));
    CHECK_EQ(ocsp.url, "http://ocsp.example/");
    CHECK_EQ(ocsp.body, (std::vector<uint8_t>{1, 2, 3}));
    CHECK_EQ(request_id(Request(ocsp)), uint64_t(7));
}

TEST(small_helpers_handle_the_cases_the_engine_does_not_produce) {
    // A null string from the library reads as absent / empty.
    CHECK(!detail::take_optional_string(nullptr).has_value());
    CHECK_EQ(detail::take_string(nullptr), "");

    // A driver with nothing to wait on reports it rather than hanging.
    detail::require_progress(true);
    CHECK_THROWS_CODE(detail::require_progress(false), ErrorCode::Read);

    // The default clock is the system clock; a pinned one is not.
    MemoryHost unpinned({});
    CHECK(unpinned.now() > 1'700'000'000);
    CHECK_EQ(MemoryHost({}, 5).now(), int64_t(5));
    bool threw = false;
    try {
        MemoryHost({1}).read(9, 1);  // start past the end, as opposed to len
    } catch (const std::out_of_range &) {
        threw = true;
    }
    CHECK(threw);
}

TEST(misusing_the_protocol_is_an_error_and_leaves_the_session_usable) {
    Session session("image/jpeg");
    Step step = session.advance();
    CHECK(!step.done);
    CHECK(!step.requests.empty());

    CHECK_THROWS_CODE(session.fulfill(~0ull, Time{0}), ErrorCode::InvalidArgument);
    // Every reply kind is accepted for marshalling, and refused by id.
    CHECK_THROWS_CODE(session.fulfill(~0ull, Ocsp{{1, 2}}), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(session.fulfill(~0ull, Length{1}), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(session.fulfill(~0ull, Bytes{{1}}), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(session.fulfill(~0ull, Failed{"x"}), ErrorCode::InvalidArgument);
    try {
        session.fulfill(~0ull, Time{0});
    } catch (const Exception &e) {
        // The message really came from the library, not a placeholder.
        CHECK(std::string(e.what()).find("no outstanding request") != std::string::npos);
        CHECK(e.name().rfind("C2pa(BadParam(", 0) == 0);
    }
    // The wrong kind of reply for the request: a clock reading for a read.
    CHECK_THROWS_CODE(session.fulfill(request_id(step.requests[0]), Time{0}), ErrorCode::Read);
}

TEST(the_request_ids_in_one_step_are_distinct_and_replies_may_come_in_any_order) {
    MemoryHost host = fixture_host();
    Session session("image/jpeg");
    bool reversed_at_least_once = false;
    for (;;) {
        Step step = session.advance();
        if (step.done) {
            break;
        }
        for (size_t i = step.requests.size(); i-- > 0;) {  // newest first
            reversed_at_least_once |= step.requests.size() > 1;
            session.fulfill(request_id(step.requests[i]), answer(host, step.requests[i]));
        }
    }
    CHECK(reversed_at_least_once);
    auto reader = std::move(session).finish();
    MemoryHost again = fixture_host();
    CHECK_EQ(json_of(reader), json_of(read(Session("image/jpeg"), again)));
}

TEST(a_pool_runs_the_engines_requests_concurrently_and_gets_the_same_answer) {
    MemoryHost reference = fixture_host();
    const std::string expected = json_of(read(Session("image/jpeg"), reference));

    SlowHost slow(std::chrono::milliseconds(10));
    {
        SimpleThreadPool pool(8);
        PooledHost host(slow, pool);
        CHECK_EQ(json_of(read_parallel(Session("image/jpeg"), host)), expected);
    }
    CHECK(slow.reads() > 1);
    CHECK(slow.max_in_flight() > 1);  // the point of the exercise

    // The same engine, the same host, one request at a time: same answer,
    // and never more than one in flight. Concurrency is the host's choice.
    SlowHost serial(std::chrono::milliseconds(0));
    CHECK_EQ(json_of(read(Session("image/jpeg"), serial)), expected);
    CHECK_EQ(serial.max_in_flight(), size_t(1));
    CHECK_EQ(serial.reads(), slow.reads());
}

TEST(a_read_can_be_a_future_and_many_can_run_at_once) {
    MemoryHost reference = fixture_host();
    const std::string expected = json_of(read(Session("image/jpeg"), reference));

    SlowHost backing(std::chrono::milliseconds(2));
    SimpleThreadPool pool(8);
    auto host = std::make_shared<PooledHost>(backing, pool);

    std::vector<std::future<std::optional<Reader>>> futures;
    for (int i = 0; i < 6; ++i) {
        futures.push_back(read_future(Session("image/jpeg"), host));
    }
    for (auto &future : futures) {
        CHECK_EQ(json_of(future.get()), expected);
    }
}

TEST(one_thread_can_multiplex_many_reads_with_no_threads_at_all) {
    MemoryHost backing = fixture_host();
    MemoryHost reference = fixture_host();
    const std::string expected = json_of(read(Session("image/jpeg"), reference));

    constexpr int kReads = 5;
    std::vector<std::unique_ptr<ManualHost>> hosts;
    std::vector<std::unique_ptr<Reading>> readings;
    std::vector<bool> finished(kReads, false);
    for (int i = 0; i < kReads; ++i) {
        hosts.push_back(std::make_unique<ManualHost>(backing));
        readings.push_back(std::make_unique<Reading>(Session("image/jpeg"), *hosts[i]));
        finished[i] = readings[i]->step();
    }

    // Round-robin, completing the *newest* parked request of each read in
    // turn: every read progresses a little at a time, interleaved with the
    // others, on this one thread.
    size_t rounds = 0;
    int remaining = kReads;
    while (remaining > 0) {
        ++rounds;
        for (int i = 0; i < kReads; ++i) {
            if (finished[i]) {
                continue;
            }
            CHECK(hosts[i]->parked() > 0);
            hosts[i]->complete(hosts[i]->parked() - 1);
            if (readings[i]->step()) {
                finished[i] = true;
                --remaining;
            }
        }
    }
    CHECK(rounds > 1);
    for (int i = 0; i < kReads; ++i) {
        CHECK_EQ(json_of(std::move(*readings[i]).finish()), expected);
        CHECK(readings[i]->max_in_flight() >= 1);
        CHECK(readings[i]->started() >= readings[i]->max_in_flight());
        CHECK_EQ(readings[i]->in_flight(), size_t(0));
    }
}

TEST(cancelling_a_read_with_requests_in_flight_is_safe) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    auto reading = std::make_unique<Reading>(Session("image/jpeg"), host);
    CHECK(!reading->step());
    CHECK(host.parked() > 0);

    // Destroying the read *is* cancelling it. The host's work is already
    // started; its completions arrive afterward, and must land nowhere
    // harmful (run under ASan in CI).
    reading.reset();
    while (host.parked() > 0) {
        host.complete(0);
    }
}

TEST(a_host_whose_start_throws_fails_that_request_not_the_driver) {
    struct Throwing : AsyncHost {
        void start(const Request &, Completion) override { throw std::runtime_error("no"); }
    } host;
    CHECK_THROWS_CODE(read_parallel(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(a_host_that_throws_something_that_is_not_an_exception_fails_the_request_too) {
    struct Throwing : AsyncHost {
        void start(const Request &, Completion) override { throw 42; }
    } host;
    CHECK_THROWS_CODE(read_parallel(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(a_session_moves_between_threads_between_calls) {
    MemoryHost host = fixture_host();
    Session session("image/jpeg");
    for (;;) {
        // Each slice of the read runs on a fresh thread: a session is
        // ordinary data, not tied to the thread that made it.
        bool done = false;
        std::thread([&] {
            Step step = session.advance();
            done = step.done;
            for (const Request &request : step.requests) {
                session.fulfill(request_id(request), answer(host, request));
            }
        }).join();
        if (done) {
            break;
        }
    }
    auto reader = std::move(session).finish();
    CHECK(reader.has_value());

    // And the finished Reader is immutable: any number of threads may query it.
    std::vector<std::thread> threads;
    std::atomic<int> agree{0};
    const std::string json = reader->json();
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            if (reader->json() == json && reader->active_label().has_value()) {
                ++agree;
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    CHECK_EQ(agree.load(), 8);
}

TEST(a_moved_from_session_and_reader_are_inert_and_move_assignment_works) {
    MemoryHost host = fixture_host();
    Session a("image/jpeg");
    Session b("jpg");
    a = std::move(b);  // frees a's old read, adopts b's
    auto first = read(std::move(a), host);
    CHECK(first.has_value());

    MemoryHost again = fixture_host();
    auto second = read(Session("image/jpeg"), again);
    first = std::move(second);
    CHECK(first.has_value());
}

TEST(the_wait_registers_a_waker_only_when_nothing_has_arrived) {
    Mailbox mailbox;
    int woke = 0;
    CHECK(mailbox.set_waker([&] { ++woke; }));
    mailbox.post(1, Time{0});
    CHECK_EQ(woke, 1);
    CHECK(!mailbox.set_waker([&] { ++woke; }));  // a reply is already waiting
    CHECK_EQ(mailbox.drain().size(), size_t(1));

    CHECK(mailbox.set_waker([&] { ++woke; }));
    mailbox.clear_waker();
    mailbox.post(2, Time{0});
    CHECK_EQ(woke, 1);  // cleared: never called
    mailbox.wait();     // returns at once: a reply is waiting
}

int main() { return check::run_all(); }
