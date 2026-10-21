// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// Non-coroutine APIs and thread-based drivers.

#include <cstdlib>
#include <sstream>
#include <type_traits>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#if defined(__unix__) || defined(__APPLE__)
#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>
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

TEST(Core, write_leases_are_move_only_and_pass_the_same_pointer_to_the_host) {
    static_assert(!std::is_copy_constructible_v<WriteBuffer>);
    static_assert(!std::is_copy_assignable_v<WriteBuffer>);
    static_assert(std::is_nothrow_move_constructible_v<WriteBuffer>);
    static_assert(std::is_nothrow_move_assignable_v<WriteBuffer>);
    WriteBuffer empty;
    EXPECT_THROW(empty.view(), std::runtime_error);
    EXPECT_THROW_CODE(WriteBuffer(nullptr, 1), ErrorCode::InvalidArgument);

    auto request = retained_write_request(1, BuildStream::Output, 0);
    const auto view = request.bytes.view();
    const std::vector<uint8_t> expected(view.data, view.data + view.size);
    WriteBuffer moved(std::move(request.bytes));
    EXPECT_THROW(request.bytes.view(), std::runtime_error);
    EXPECT_EQ(moved.view().data, view.data);
    auto replaced = retained_write_request(2, BuildStream::Output, 0);
    replaced.bytes = std::move(moved);
    EXPECT_THROW(moved.view(), std::runtime_error);
    auto &alias = replaced.bytes;
    replaced.bytes = std::move(alias);
    EXPECT_EQ(replaced.bytes.view().data, view.data);

    struct PointerHost : MemoryBuildHost {
        using MemoryBuildHost::MemoryBuildHost;
        const uint8_t *expected_pointer = nullptr;
        bool observed = false;
        void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override {
            EXPECT_EQ(bytes.data, expected_pointer);
            observed = true;
            MemoryBuildHost::write(stream, offset, bytes);
        }
    } host(fixture_bytes(), fixture_sign);
    host.expected_pointer = view.data;
    BuildRequest pending = std::move(replaced);
    EXPECT_TRUE(std::holds_alternative<Written>(answer(host, pending)));
    EXPECT_TRUE(host.observed);
    EXPECT_EQ(host.output(), expected);
    EXPECT_EQ(std::get<WriteRequest>(pending).bytes.view().data, view.data);

    BuildRequest invalid = WriteRequest{3, BuildStream::Output, 0, WriteBuffer{}};
    EXPECT_TRUE(std::holds_alternative<Failed>(answer(host, invalid)));
}

TEST(Core, validation_state_is_typed_and_independent_of_json_formatting) {
    for (bool valid_signature : {false, true}) {
        BuildSigner signer = valid_signature ? BuildSigner(fixture_sign) :
            BuildSigner([](const auto &, const auto &) { return std::vector<uint8_t>(64); });
        MemoryBuildHost builder(fixture_bytes(), std::move(signer));
        build_and_sign(BuildSession(signing_settings()), builder);
        for (bool trusted : {false, true}) {
            MemoryHost host(builder.output(), kNow);
            auto reader = read(Session("image/jpeg",
                trusted ? std::optional<std::string>(signing_trust_settings()) : std::nullopt), host);
            EXPECT_TRUE(reader.has_value());
            const auto expected = !valid_signature ? ValidationState::Invalid :
                trusted ? ValidationState::Trusted : ValidationState::Valid;
            EXPECT_TRUE(reader->validation_state() == expected);
            auto moved = std::move(*reader);
            EXPECT_TRUE(moved.validation_state() == expected);
            EXPECT_THROW_CODE(reader->validation_state(), ErrorCode::InvalidArgument);
        }
    }
}

TEST(Core, build_session_is_move_only_and_rejects_invalid_settings) {
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
    EXPECT_TRUE(rejected);
}

TEST(Core, build_settings_reject_embedded_nuls_without_truncation) {
    for (int field = 0; field < 3; ++field) {
        auto settings = signing_settings();
        auto &value = field == 0 ? settings.definition_json : field == 1 ? settings.format : settings.algorithm;
        value.push_back('\0');
        value += "ignored suffix";
        EXPECT_THROW_CODE(BuildSession(settings), ErrorCode::InvalidArgument);
    }
}

TEST(Core, async_build_rejects_overlapping_driver_calls_without_consuming_the_session) {
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
    EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    { std::lock_guard<std::mutex> lock(host.mutex); host.released = true; }
    host.ready.notify_all();
    driver.join();
    EXPECT_TRUE(!driver_error);
    host.deliver();
    while (!building.step()) host.deliver();
    EXPECT_TRUE(!std::move(building).finish().manifest.empty());
    EXPECT_TRUE(trusted_signing_json(host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(Core, async_builds_interleave_without_redispatch_or_empty_batch_completion) {
    ManualBuildHost first_host, second_host;
    Building first(BuildSession(signing_settings()), first_host);
    Building second(BuildSession(signing_settings()), second_host);
    bool first_done = false, second_done = false;
    while (!first_done || !second_done) {
        if (!first_done) first_done = first.step();
        if (!second_done) second_done = second.step();
        if (!first_done) {
            const auto count = first.started();
            EXPECT_TRUE(!first.step());
            EXPECT_EQ(first.started(), count);
        }
        first_host.deliver();
        second_host.deliver();
    }
    EXPECT_TRUE(!std::move(first).finish().manifest.empty());
    EXPECT_TRUE(!std::move(second).finish().manifest.empty());
    EXPECT_TRUE(trusted_signing_json(first_host.backing.output()).find("Trusted") != std::string::npos);
    EXPECT_TRUE(trusted_signing_json(second_host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(Core, async_build_moves_cancel_late_callbacks_and_preserve_request_storage) {
    static_assert(!std::is_copy_constructible_v<Building>);
    static_assert(std::is_nothrow_move_assignable_v<Building>);
    ManualBuildHost host;
    {
        Building original(BuildSession(signing_settings()), host);
        EXPECT_TRUE(!original.step());
        Building moved(std::move(original));
        EXPECT_THROW_CODE(original.step(), ErrorCode::InvalidArgument);
        Building assigned(BuildSession(signing_settings()), host);
        assigned = std::move(moved);
        EXPECT_THROW_CODE(moved.step(), ErrorCode::InvalidArgument);
        EXPECT_TRUE(assigned.in_flight() > 0);
        EXPECT_EQ(assigned.max_in_flight(), assigned.in_flight());
        EXPECT_TRUE(assigned.mailbox().set_waker([] { throw std::runtime_error("cancelled waker ran"); }));
    }
    host.deliver();
    EXPECT_TRUE(host.pending.empty());
}

TEST(Core, build_mailbox_wakers_cover_delivery_registration_race_and_reentry) {
    for (int iteration = 0; iteration < 32; ++iteration) {
        BuildMailbox mailbox;
        std::atomic<int> wakes{0};
        std::thread delivery([&] { mailbox.post(7, Length{9}); });
        const bool registered = mailbox.set_waker([&] { ++wakes; mailbox.clear_waker(); });
        delivery.join();
        EXPECT_EQ(wakes.load(), registered ? 1 : 0);
        mailbox.wait();
        EXPECT_TRUE(!mailbox.set_waker([] {}));
        EXPECT_EQ(mailbox.drain().size(), size_t{1});
        EXPECT_TRUE(mailbox.set_waker([&] { ++wakes; }));
        mailbox.clear_waker();
        mailbox.post(8, Written{});
        EXPECT_EQ(wakes.load(), registered ? 1 : 0);
    }
}

TEST(Core, build_mailbox_preserves_replies_when_wakers_throw_and_discards_them_on_cancel) {
    BuildMailbox mailbox;
    for (bool standard_error : {false, true}) {
        int wakes = 0;
        EXPECT_TRUE(mailbox.set_waker([&] {
            ++wakes;
            if (standard_error) throw std::runtime_error("waker failed");
            throw 42;
        }));
        mailbox.post(7, Length{9});
        mailbox.wait();
        const auto messages = mailbox.drain();
        EXPECT_EQ(wakes, 1);
        EXPECT_EQ(messages.size(), size_t{1});
        EXPECT_EQ(messages.front().first, uint64_t{7});
        EXPECT_EQ(std::get<Length>(messages.front().second).value, uint64_t{9});
        EXPECT_TRUE(mailbox.drain().empty());
    }
    ManualBuildHost host;
    Building building(BuildSession(signing_settings()), host);
    auto &cancelled = building.mailbox();
    int wakes = 0;
    EXPECT_TRUE(cancelled.set_waker([&] { ++wakes; }));
    EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    cancelled.wait();
    EXPECT_TRUE(!cancelled.set_waker([&] { ++wakes; }));
    cancelled.post(8, Written{});
    EXPECT_TRUE(cancelled.drain().empty());
    EXPECT_EQ(wakes, 0);
    EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
}

TEST(Core, build_mailbox_wait_blocks_until_a_reply_or_cancellation) {
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
        EXPECT_TRUE(waiter.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
        if (cancel) {
            EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
        } else {
            mailbox.post(7, Length{9});
        }
        waiter.get();
        EXPECT_EQ(mailbox.drain().size(), cancel ? size_t{0} : size_t{1});
    }
}

TEST(Core, async_build_protocol_errors_are_terminal_instead_of_hanging) {
    for (bool bad_id : {false, true}) {
        ManualBuildHost host;
        Building building(BuildSession(signing_settings()), host);
        EXPECT_TRUE(!building.step());
        building.mailbox().post(bad_id ? UINT64_MAX : request_id(host.pending.front().first), Signature{{}});
        EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
        EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
        EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
        host.deliver();
    }
    ManualBuildHost host;
    Building premature(BuildSession(signing_settings()), host);
    EXPECT_THROW_CODE(std::move(premature).finish(), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(premature.step(), ErrorCode::InvalidArgument);
}

class InlineBuildHost : public AsyncBuildHost {
public:
    MemoryBuildHost backing{fixture_bytes(), fixture_sign};
    Building *operation = nullptr;
    int failure = 0;
    void start(BuildRequest request, BuildCompletion done) override {
        if (failure == 1) throw std::runtime_error("start failed");
        if (failure == 2) throw 42;
        if (operation) {
            EXPECT_THROW_CODE(operation->step(), ErrorCode::InvalidArgument);
        }
        done(answer(backing, request));
        done(Failed{"duplicate ignored"});
        throw std::runtime_error("completion already won");
    }
};

TEST(Core, inline_build_callbacks_do_not_recurse_and_finish_is_consumed) {
    InlineBuildHost host;
    Building building(BuildSession(signing_settings()), host);
    host.operation = &building;
    while (!building.step()) building.mailbox().wait();
    const auto count = building.started();
    EXPECT_TRUE(building.step());
    EXPECT_EQ(building.started(), count);
    EXPECT_EQ(building.in_flight(), size_t{0});
    EXPECT_TRUE(!std::move(building).finish().manifest.empty());
    EXPECT_THROW_CODE(building.step(), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(std::move(building).finish(), ErrorCode::InvalidArgument);
    EXPECT_TRUE(trusted_signing_json(host.backing.output()).find("Trusted") != std::string::npos);
}

TEST(Core, build_futures_own_progress_and_deliver_standard_and_nonstandard_start_errors) {
    for (int failure : {0, 1, 2}) {
        auto host = std::make_shared<InlineBuildHost>();
        host->failure = failure;
        auto future = build_future(BuildSession(signing_settings()), host);
        if (failure) {
            EXPECT_THROW_CODE(future.get(), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
        } else {
            EXPECT_TRUE(!future.get().manifest.empty());
        }
    }
    EXPECT_THROW_CODE(build_future(BuildSession(signing_settings()), nullptr), ErrorCode::InvalidArgument);
}

TEST(Core, pooled_build_submission_failure_and_throwing_completion_do_not_escape_workers) {
    struct RejectingPool : ThreadPool {
        void post(std::function<void()>) override { throw std::runtime_error("pool rejected task"); }
    } rejected;
    MemoryBuildHost backing(fixture_bytes(), fixture_sign);
    PooledBuildHost refused(backing, rejected);
    EXPECT_THROW_CODE(build_parallel(BuildSession(signing_settings()), refused),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    EXPECT_THROW_CODE(PooledBuildHost(std::shared_ptr<SyncBuildHost>{}, rejected), ErrorCode::InvalidArgument);
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
    EXPECT_EQ(std::get<Length>(reply).value, backing.length(BuildStream::Source));
}

TEST(Core, pooled_build_failures_release_the_host_for_later_requests) {
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
        EXPECT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message,
                 stream == BuildStream::Source ? "length refused" : "unknown build host error");
    }
    std::promise<BuildReply> result;
    auto future = result.get_future();
    auto request = retained_write_request(2, BuildStream::Output, 0);
    const auto bytes = request.bytes.view();
    const std::vector<uint8_t> expected(bytes.data, bytes.data + bytes.size);
    adapter.start(std::move(request), [&](BuildReply reply) {
        result.set_value(std::move(reply));
    });
    EXPECT_TRUE(std::holds_alternative<Written>(future.get()));
    pool.reset();
    EXPECT_EQ(host.output(), expected);
}

TEST(Core, pooled_builds_round_trip_memory_and_seekable_streams) {
    auto pool = make_simple_thread_pool(4);
    auto memory = std::make_shared<MemoryBuildHost>(fixture_bytes(), fixture_sign);
    auto pooled = std::make_shared<PooledBuildHost>(memory, *pool);
    EXPECT_TRUE(!build_future(BuildSession(signing_settings()), pooled).get().manifest.empty());
    EXPECT_TRUE(trusted_signing_json(memory->output()).find("Trusted") != std::string::npos);
    const auto source_bytes = fixture_bytes();
    std::istringstream source(std::string(source_bytes.begin(), source_bytes.end()));
    std::stringstream output;
    IOStreamBuildHost streams(source, output, fixture_sign);
    PooledBuildHost stream_pool(streams, *pool);
    EXPECT_TRUE(!build_parallel(BuildSession(signing_settings()), stream_pool).manifest.empty());
    const auto bytes = output.str();
    EXPECT_TRUE(trusted_signing_json({bytes.begin(), bytes.end()}).find("Trusted") != std::string::npos);
}

TEST(Core, pooled_build_host_serializes_competing_writes_to_mutable_output) {
    struct ControlledHost : MemoryBuildHost {
        ControlledHost() : MemoryBuildHost({}) {}
        std::mutex mutex;
        std::condition_variable ready;
        bool entered = false, released = false;
        std::atomic<int> active{0};
        std::atomic<bool> overlapped{false};
        void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override {
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
    auto first = retained_write_request(1, BuildStream::Output, 0);
    const auto bytes = first.bytes.view();
    const std::vector<uint8_t> payload(bytes.data, bytes.data + bytes.size);
    adapter.start(std::move(first), complete);
    {
        std::unique_lock<std::mutex> lock(host.mutex);
        host.ready.wait(lock, [&] { return host.entered; });
    }
    for (uint64_t index = 1; index < 8; ++index)
        adapter.start(retained_write_request(index + 1, BuildStream::Output, index * payload.size()), complete);
    {
        std::unique_lock<std::mutex> lock(host.mutex);
        host.released = true;
        host.ready.notify_all();
        host.ready.wait(lock, [&] { return finished == 8; });
    }
    pool.reset();
    EXPECT_EQ(written, size_t{8});
    EXPECT_TRUE(!host.overlapped.load());
    EXPECT_EQ(host.active.load(), 0);
    std::vector<uint8_t> expected;
    for (size_t index = 0; index < 8; ++index) expected.insert(expected.end(), payload.begin(), payload.end());
    EXPECT_EQ(host.output(), expected);
}

TEST(Core, pooled_adapter_and_operation_can_die_while_owned_host_work_is_in_flight) {
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
    EXPECT_TRUE(!retained.expired());
    { std::lock_guard<std::mutex> lock(mutex); released = true; }
    ready.notify_all();
    pool.reset();
    EXPECT_TRUE(retained.expired());
}

TEST(Core, blocking_signing_round_trips_trusted_with_owned_report) {
    auto settings = signing_settings();
    BuildSession session(settings);
    settings.definition_json.clear();
    settings.certificates.clear();
    MemoryBuildHost host(fixture_bytes(), fixture_sign);
    auto report = build_and_sign(std::move(session), host);
    const auto json = trusted_signing_json(host.output());
    EXPECT_TRUE(json.find("Trusted") != std::string::npos);
    EXPECT_TRUE(json.find("baseline.jpg") != std::string::npos);
    EXPECT_TRUE(json.find("c2pa.actions.v2") != std::string::npos);
    EXPECT_TRUE(!report.manifest.empty());
    EXPECT_TRUE(!report.exclusions.empty());
    uint64_t previous = 0;
    for (const auto &range : report.exclusions) {
        EXPECT_TRUE(range.start >= previous);
        EXPECT_TRUE(range.start <= host.output().size());
        EXPECT_TRUE(range.len <= host.output().size() - range.start);
        previous = range.start;
    }
    const auto copied = report;
    report.manifest.clear();
    report.exclusions.clear();
    EXPECT_TRUE(!copied.manifest.empty());
    EXPECT_TRUE(!copied.exclusions.empty());
}

TEST(Core, build_session_moves_consumes_and_preserves_owned_pending_values) {
    BuildSession original(signing_settings());
    auto first = original.advance();
    EXPECT_TRUE(!first.done);
    EXPECT_TRUE(!first.requests.empty());
    EXPECT_TRUE(original.advance().requests.empty());
    EXPECT_TRUE(!original.advance().done);
    BuildSession moved(std::move(original));
    EXPECT_THROW_CODE(original.advance(), ErrorCode::InvalidArgument);
    BuildSession assigned(signing_settings());
    assigned = std::move(moved);
    EXPECT_THROW_CODE(moved.fulfill(0, Failed{"moved"}), ErrorCode::InvalidArgument);
    const auto id = request_id(first.requests.front());
    EXPECT_THROW_CODE(assigned.fulfill(id, Signature{{}}), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(assigned.fulfill(UINT64_MAX, Length{0}), ErrorCode::InvalidArgument);
    MemoryBuildHost host(fixture_bytes(), fixture_sign);
    for (auto &pending : first.requests) assigned.fulfill(request_id(pending), answer(host, pending));
    EXPECT_THROW_CODE(assigned.fulfill(id, Length{0}), ErrorCode::InvalidArgument);
    std::vector<BuildRequest> retained;
    for (;;) {
        auto step = assigned.advance();
        if (step.done) break;
        EXPECT_TRUE(!step.requests.empty());
        if (step.requests.empty()) throw std::runtime_error("unexpected stalled build");
        for (auto &pending : step.requests) {
            assigned.fulfill(request_id(pending), answer(host, pending));
            retained.push_back(std::move(pending));
        }
    }
    const auto report = std::move(assigned).finish();
    EXPECT_TRUE(!report.manifest.empty());
    EXPECT_THROW_CODE(assigned.advance(), ErrorCode::InvalidArgument);
    bool saw_sign = false;
    bool saw_write = false;
    for (const auto &pending : retained) {
        if (const auto *sign = std::get_if<SignRequest>(&pending)) {
            EXPECT_EQ(sign->algorithm, "es256");
            EXPECT_TRUE(!sign->data.empty());
            saw_sign = true;
        }
        if (const auto *write = std::get_if<WriteRequest>(&pending)) {
            EXPECT_TRUE(write->bytes.view().size != 0);
            saw_write = true;
        }
    }
    EXPECT_TRUE(saw_sign && saw_write);
}

TEST(Core, premature_finish_consumes_build_and_moved_from_finish_is_safe) {
    BuildSession session(signing_settings());
    EXPECT_THROW_CODE(std::move(session).finish(), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(std::move(session).finish(), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(session.advance(), ErrorCode::InvalidArgument);
}

TEST(Core, signing_read_leases_are_move_only_and_survive_session_destruction) {
    static_assert(!std::is_copy_constructible_v<ReadBuffer>);
    static_assert(!std::is_copy_constructible_v<CompletedRead>);
    ReadBuffer retained;
    {
        BuildSession session(signing_settings());
        MemoryBuildHost host(fixture_bytes(), fixture_sign);
        bool acquired = false;
        while (!acquired) {
            auto step = session.advance();
            ASSERT_FALSE(step.done);
            ASSERT_FALSE(step.requests.empty());
            for (auto &pending : step.requests) {
                if (auto *read = std::get_if<BuildReadRequest>(&pending)) {
                    retained = std::move(read->destination);
                    acquired = true;
                } else {
                    session.fulfill(request_id(pending), answer(host, pending));
                }
            }
        }
    }
    const auto bytes = retained.writable();
    ASSERT_GT(bytes.size, size_t{0});
    std::fill_n(bytes.data, bytes.size, uint8_t{42});
    ReadBuffer moved(std::move(retained));
    EXPECT_THROW(retained.writable(), std::runtime_error);
    EXPECT_EQ(moved.writable().data, bytes.data);
    EXPECT_THROW_CODE(std::move(moved).seal(bytes.size - 1), ErrorCode::InvalidArgument);
    EXPECT_EQ(moved.writable().data, bytes.data);
    ReadBuffer assigned;
    assigned = std::move(moved);
    EXPECT_THROW(moved.writable(), std::runtime_error);
    auto completed = std::move(assigned).seal(bytes.size);
    EXPECT_THROW(assigned.writable(), std::runtime_error);
    CompletedRead sealed(std::move(completed));
    completed = std::move(sealed);
    EXPECT_THROW_CODE(std::move(assigned).seal(bytes.size), ErrorCode::InvalidArgument);
}

TEST(Core, sealed_read_wrong_routing_does_not_consume_the_completion) {
    BuildSession session(signing_settings());
    MemoryBuildHost host(fixture_bytes(), fixture_sign);
    for (;;) {
        auto step = session.advance();
        ASSERT_FALSE(step.done);
        ASSERT_FALSE(step.requests.empty());
        for (auto &pending : step.requests) {
            const auto id = request_id(pending);
            auto reply = answer(host, pending);
            if (std::holds_alternative<CompletedRead>(reply)) {
                EXPECT_THROW_CODE(session.fulfill(UINT64_MAX, std::move(reply)), ErrorCode::InvalidArgument);
                EXPECT_NO_THROW(session.fulfill(id, std::move(reply)));
                EXPECT_THROW_CODE(session.fulfill(id, std::move(reply)), ErrorCode::InvalidArgument);
                return;
            }
            session.fulfill(id, std::move(reply));
        }
    }
}

TEST(Core, memory_build_host_keeps_streams_distinct_and_checks_bounds) {
    MemoryBuildHost host({1, 2, 3});
    EXPECT_EQ(host.length(BuildStream::Source), uint64_t(3));
    EXPECT_EQ(host.length(BuildStream::Output), uint64_t(0));
    const uint8_t bytes[] = {9, 8};
    host.write(BuildStream::Output, 1, {bytes, sizeof(bytes)});
    EXPECT_EQ(read_build_host(host, BuildStream::Source, 1, 2), (std::vector<uint8_t>{2, 3}));
    EXPECT_EQ(read_build_host(host, BuildStream::Output, 0, 3), (std::vector<uint8_t>{0, 9, 8}));
    EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Source, 2, 2)));
    EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Output, UINT64_MAX, 1)));
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Output, UINT64_MAX, {1})));
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Source, 0, {1})));
    EXPECT_TRUE(std::holds_alternative<Written>(write_build_reply(host, BuildStream::Output, 0, {1})));
    EXPECT_EQ(std::get<Length>(answer(host, BuildLengthRequest{1, BuildStream::Output})).value, uint64_t(3));
}

TEST(Core, build_request_conversion_rejects_unknown_abi_values) {
    bool rejected = false;
    try { detail::build_stream(99); } catch (const std::runtime_error &) { rejected = true; }
    EXPECT_TRUE(rejected);
    C2paSmBuildRequest pending{};
    pending.kind = 99;
    rejected = false;
    try { detail::describe(nullptr, pending); } catch (const std::runtime_error &) { rejected = true; }
    EXPECT_TRUE(rejected);
}

TEST(Core, build_request_conversion_accepts_empty_buffers_without_dereferencing_them) {
    EXPECT_TRUE(detail::build_bytes({nullptr, 0}).empty());
    EXPECT_TRUE(detail::build_string({nullptr, 0}).empty());
    C2paSmBuildRequest pending{};
    pending.id = 42;
    pending.kind = C2PA_SM_BUILD_REQUEST_SIGN;
    const auto sign = std::get<SignRequest>(detail::describe(nullptr, pending));
    EXPECT_EQ(sign.id, uint64_t(42));
    EXPECT_TRUE(sign.algorithm.empty());
    EXPECT_TRUE(sign.data.empty());
    pending.kind = C2PA_SM_BUILD_REQUEST_TIMESTAMP;
    const auto timestamp = std::get<TimestampRequest>(detail::describe(nullptr, pending));
    EXPECT_EQ(timestamp.id, uint64_t(42));
    EXPECT_TRUE(timestamp.url.empty());
    EXPECT_TRUE(timestamp.body.empty());
    pending.kind = C2PA_SM_BUILD_REQUEST_WRITE;
    pending.stream = C2PA_SM_BUILD_OUTPUT;
    EXPECT_THROW_CODE(detail::describe(nullptr, pending), ErrorCode::InvalidArgument);
}

TEST(Core, build_request_conversion_copies_nonempty_payloads_without_terminators) {
    std::vector<uint8_t> bytes{1, 0, 3};
    std::string text = "es256";
    C2paSmBuildRequest pending{};
    pending.id = 42;
    pending.data = {bytes.data(), bytes.size()};
    pending.algorithm = {reinterpret_cast<const uint8_t *>(text.data()), text.size()};
    pending.url = pending.algorithm;
    pending.kind = C2PA_SM_BUILD_REQUEST_SIGN;
    const auto sign = std::get<SignRequest>(detail::describe(nullptr, pending));
    pending.kind = C2PA_SM_BUILD_REQUEST_TIMESTAMP;
    const auto timestamp = std::get<TimestampRequest>(detail::describe(nullptr, pending));
    bytes.assign(bytes.size(), 0);
    text.assign(text.size(), 'x');
    EXPECT_EQ(sign.algorithm, "es256");
    EXPECT_EQ(sign.data, (std::vector<uint8_t>{1, 0, 3}));
    EXPECT_EQ(timestamp.url, "es256");
    EXPECT_EQ(timestamp.body, sign.data);
}

TEST(Core, build_hosts_accept_empty_io_at_eof_without_changing_output) {
    MemoryBuildHost memory({1, 2, 3});
    std::istringstream source("abc");
    std::stringstream output;
    IOStreamBuildHost streams(source, output);
    for (SyncBuildHost *host : {static_cast<SyncBuildHost *>(&memory), static_cast<SyncBuildHost *>(&streams)}) {
        EXPECT_TRUE(read_build_host(*host, BuildStream::Source, 3, 0).empty());
        EXPECT_TRUE(read_build_host(*host, BuildStream::Output, 0, 0).empty());
        EXPECT_TRUE(std::holds_alternative<Written>(write_build_reply(*host, BuildStream::Output, 0, {})));
        EXPECT_EQ(host->length(BuildStream::Output), uint64_t(0));
        EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(*host, BuildStream::Source, 4, 0)));
    }
    EXPECT_TRUE(memory.output().empty());
    EXPECT_TRUE(output.str().empty());
}

TEST(Core, blocking_signing_supports_seekable_iostreams) {
    const auto source = fixture_bytes();
    std::istringstream input(std::string(source.begin(), source.end()));
    std::stringstream output;
    IOStreamBuildHost host(input, output, fixture_sign);
    const auto report = build_and_sign(BuildSession(signing_settings()), host);
    EXPECT_TRUE(!report.manifest.empty());
    const auto bytes = output.str();
    EXPECT_TRUE(trusted_signing_json({bytes.begin(), bytes.end()}).find("Trusted") != std::string::npos);
}

TEST(Core, stream_host_rejects_alias_nonempty_failed_and_short_io) {
    std::stringstream input("abc");
    std::stringstream output;
    bool rejected = false;
    try { IOStreamBuildHost host(input, input); } catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
    rejected = false;
    try { IOStreamBuildHost host(output, input); } catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
    IOStreamBuildHost host(input, output);
    EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Source, 2, 2)));
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Source, 0, {1})));
    output.setstate(std::ios::badbit);
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Output, 0, {1})));
    EXPECT_TRUE(std::holds_alternative<Failed>(answer(host, BuildLengthRequest{1, BuildStream::Output})));
    input.exceptions(std::ios::badbit);
    try { input.setstate(std::ios::badbit); } catch (const std::exception &) {}
    EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Source, 0, 1)));
}

TEST(Core, stream_host_detects_short_reads_short_writes_flush_and_seek_failures) {
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
    EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(reader, BuildStream::Source, 0, 3)));
    std::istringstream input("abc");
    std::iostream short_output(&short_write);
    IOStreamBuildHost writer(input, short_output);
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(writer, BuildStream::Output, 0, {1, 2, 3})));
    std::iostream unflushed(&failed_flush);
    IOStreamBuildHost flushing(input, unflushed);
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(flushing, BuildStream::Output, 0, {1})));
    EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(reader, BuildStream::Output, UINT64_MAX, {1})));
    struct Unseekable : std::streambuf {} unseekable;
    std::iostream invalid(&unseekable);
    bool rejected = false;
    try { IOStreamBuildHost host(input, invalid); } catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
}

TEST(Core, stream_host_converts_exceptions_from_each_io_operation_into_failures) {
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
            EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Source, 0, 1)));
        }
        if (operation != ThrowingBuffer::Operation::Read && operation != ThrowingBuffer::Operation::Tell) {
            output_buffer.operation = operation;
            EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Output, 0, {1})));
        }
    }
}

TEST(Core, stream_host_rejects_an_unavailable_current_position_after_a_successful_seek) {
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
    EXPECT_TRUE(std::holds_alternative<Failed>(answer(host, BuildLengthRequest{1, BuildStream::Source})));
    EXPECT_TRUE(source.good());
}

TEST(Core, missing_throwing_and_invalid_signers_fail_the_build) {
    const std::vector<BuildSigner> signers{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("signer refused"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1}; },
    };
    for (const auto &signer : signers) {
        MemoryBuildHost host(fixture_bytes(), signer);
        EXPECT_THROW_CODE(build_and_sign(BuildSession(signing_settings()), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
}

TEST(Core, timestamp_callback_receives_url_and_der_and_failures_fail_closed) {
    std::vector<BuildTimestamp> callbacks{
        {},
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw std::runtime_error("offline"); },
        [](const auto &, const auto &) -> std::vector<uint8_t> { throw 42; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{1, 2}; },
        [](const auto &, const auto &) { return std::vector<uint8_t>{0x30, 5, 0x30, 3, 2, 1, 2}; },
    };
    for (const auto &callback : callbacks) {
        MemoryBuildHost host(fixture_bytes(), fixture_sign, callback);
        EXPECT_THROW_CODE(build_and_sign(BuildSession(signing_settings(true)), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
    bool called = false;
    MemoryBuildHost host(fixture_bytes(), fixture_sign, [&](const auto &url, const auto &body) {
        EXPECT_EQ(url, "https://tsa.example/");
        EXPECT_TRUE(!body.empty() && body.front() == 0x30);
        called = true;
        return std::vector<uint8_t>{0x30, 8, 0x30, 3, 2, 1, 0, 0x30, 1, 0};
    });
    const auto report = build_and_sign(BuildSession(signing_settings(true)), host);
    EXPECT_TRUE(called);
    EXPECT_TRUE(!report.manifest.empty());
}

TEST(Core, short_reads_and_host_failures_fail_without_spinning) {
    struct Broken : MemoryBuildHost {
        explicit Broken(int failure) : MemoryBuildHost(fixture_bytes(), fixture_sign), failure_(failure) {}
        void read_into(BuildStream stream, uint64_t start, MutableBytes destination) override {
            if (failure_ == 0) throw std::runtime_error("short read");
            MemoryBuildHost::read_into(stream, start, destination);
        }
        uint64_t length(BuildStream stream) override {
            if (failure_ == 1) throw std::runtime_error("length failed");
            return MemoryBuildHost::length(stream);
        }
        void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override {
            if (failure_ == 2) throw 42;
            MemoryBuildHost::write(stream, offset, bytes);
        }
        int failure_;
    };
    for (int failure = 0; failure < 3; ++failure) {
        Broken host(failure);
        EXPECT_THROW_CODE(build_and_sign(BuildSession(signing_settings()), host), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    }
}

#if defined(__unix__) || defined(__APPLE__)
TEST(Core, file_build_read_reports_source_truncation_after_length_check) {
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
        const auto reply = read_build_reply(host, BuildStream::Source, 0, 3);
        EXPECT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message, "build file read failed");
    }
    EXPECT_EQ(std::filesystem::file_size(source), uintmax_t{0});
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                           std::filesystem::directory_iterator{}), 1);
}

TEST(Core, file_signing_publishes_only_success_and_cleans_temporaries) {
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
        EXPECT_EQ(::getrlimit(RLIMIT_FSIZE, &initial_limit), 0);
        EXPECT_EQ(::sigaction(SIGXFSZ, nullptr, &initial_action), 0);
        const auto reply = [&host] {
            FileSizeLimit limit(3);
            return write_build_reply(host, BuildStream::Output, 0, {1, 2, 3, 4, 5});
        }();
        struct rlimit restored_limit{};
        struct sigaction restored_action{};
        EXPECT_EQ(::getrlimit(RLIMIT_FSIZE, &restored_limit), 0);
        EXPECT_EQ(::sigaction(SIGXFSZ, nullptr, &restored_action), 0);
        EXPECT_EQ(restored_limit.rlim_cur, initial_limit.rlim_cur);
        EXPECT_EQ(restored_limit.rlim_max, initial_limit.rlim_max);
        EXPECT_TRUE(restored_action.sa_handler == initial_action.sa_handler);
        EXPECT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message, "build file write failed");
        EXPECT_EQ(host.length(BuildStream::Output), uint64_t(3));
        EXPECT_EQ(read_build_host(host, BuildStream::Output, 0, 3), (std::vector<uint8_t>{1, 2, 3}));
    }
    EXPECT_TRUE(std::filesystem::is_empty(cleanup.path));
    {
        FileBuildHost host(C2PA_SM_FIXTURE, destination);
        const auto source_length = host.length(BuildStream::Source);
        EXPECT_TRUE(source_length > 0);
        EXPECT_TRUE(read_build_host(host, BuildStream::Source, source_length, 0).empty());
        EXPECT_TRUE(read_build_host(host, BuildStream::Output, 0, 0).empty());
        EXPECT_TRUE(std::holds_alternative<Written>(write_build_reply(host, BuildStream::Output, 0, {})));
        EXPECT_EQ(host.length(BuildStream::Output), uint64_t(0));
        EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Source, source_length, 1)));
        EXPECT_TRUE(std::holds_alternative<Failed>(read_build_reply(host, BuildStream::Output, UINT64_MAX, 1)));
        EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Source, 0, {1})));
        EXPECT_TRUE(std::holds_alternative<Failed>(write_build_reply(host, BuildStream::Output, UINT64_MAX, {1})));
        EXPECT_EQ(host.length(BuildStream::Source), source_length);
        EXPECT_EQ(host.length(BuildStream::Output), uint64_t(0));
    }
    EXPECT_TRUE(std::filesystem::is_empty(cleanup.path));
    {
        std::ofstream output(destination);
        output << "keep me";
    }
    EXPECT_THROW_CODE(build_and_sign_file(BuildSettings{}, C2PA_SM_FIXTURE, destination, fixture_sign),
                      ErrorCode::InvalidArgument);
    {
        std::ifstream input(destination);
        EXPECT_EQ(std::string(std::istreambuf_iterator<char>(input), {}), "keep me");
    }
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                           std::filesystem::directory_iterator{}), 1);
    EXPECT_THROW_CODE(build_and_sign_file(settings, C2PA_SM_FIXTURE, destination, {}), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    {
        std::ifstream input(destination);
        EXPECT_EQ(std::string(std::istreambuf_iterator<char>(input), {}), "keep me");
    }
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 1);
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
            EXPECT_THROW_CODE(build_and_sign_file(signing_settings(true), C2PA_SM_FIXTURE, output_path,
                                                  fixture_sign, timestamp),
                              static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
            std::ifstream preserved(destination);
            EXPECT_EQ(std::string(std::istreambuf_iterator<char>(preserved), {}), "keep me");
            EXPECT_TRUE(!std::filesystem::exists(absent));
            EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path),
                                   std::filesystem::directory_iterator{}), 1);
        }
    }
    const auto report = build_and_sign_file(settings, C2PA_SM_FIXTURE, destination, fixture_sign);
    EXPECT_TRUE(!report.manifest.empty());
    struct stat published{};
    EXPECT_EQ(::stat(destination.c_str(), &published), 0);
    EXPECT_EQ(published.st_mode & 0777, 0600);
    std::ifstream input(destination, std::ios::binary);
    const std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(input), {});
    EXPECT_TRUE(trusted_signing_json(bytes).find("Trusted") != std::string::npos);
    const auto in_place = cleanup.path / "in-place.jpg";
    std::filesystem::copy_file(destination, in_place);
    EXPECT_THROW_CODE(build_and_sign_file(settings, in_place, in_place, {}),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    {
        std::ifstream preserved(in_place, std::ios::binary);
        EXPECT_EQ(std::vector<uint8_t>(std::istreambuf_iterator<char>(preserved), {}), bytes);
    }
    EXPECT_TRUE(!build_and_sign_file(settings, in_place, in_place, fixture_sign).manifest.empty());
    EXPECT_EQ(::stat(in_place.c_str(), &published), 0);
    EXPECT_EQ(published.st_mode & 0777, 0600);
    {
        std::ifstream signed_input(in_place, std::ios::binary);
        const std::vector<uint8_t> signed_bytes(std::istreambuf_iterator<char>(signed_input), {});
        EXPECT_TRUE(trusted_signing_json(signed_bytes).find("Trusted") != std::string::npos);
    }
    std::filesystem::remove(in_place);
    const auto directory = cleanup.path / "cannot-replace";
    std::filesystem::create_directory(directory);
    bool rejected = false;
    try { build_and_sign_file(settings, C2PA_SM_FIXTURE, directory, fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
    EXPECT_TRUE(std::filesystem::is_directory(directory));
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 2);
    rejected = false;
    try { build_and_sign_file(settings, cleanup.path / "missing.jpg", destination, fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 2);
    const auto link = cleanup.path / "link.jpg";
    std::filesystem::create_symlink(destination, link);
    EXPECT_THROW_CODE(build_and_sign_file(settings, C2PA_SM_FIXTURE, link, {}), static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    EXPECT_TRUE(std::filesystem::is_symlink(link));
    build_and_sign_file(settings, C2PA_SM_FIXTURE, link, fixture_sign);
    EXPECT_TRUE(!std::filesystem::is_symlink(link));
    std::ifstream unchanged(destination, std::ios::binary);
    EXPECT_EQ(std::vector<uint8_t>(std::istreambuf_iterator<char>(unchanged), {}), bytes);
    rejected = false;
    try { build_and_sign_file(settings, C2PA_SM_FIXTURE, cleanup.path / "missing" / "out.jpg", fixture_sign); }
    catch (const std::exception &) { rejected = true; }
    EXPECT_TRUE(rejected);
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
        EXPECT_TRUE(rejected);
    }
    EXPECT_THROW_CODE(build_and_sign_file(settings, cleanup.path, destination, fixture_sign),
                      static_cast<ErrorCode>(C2PA_SM_ERR_BUILD));
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(cleanup.path), std::filesystem::directory_iterator{}), 3);
}
#endif

TEST(Core, signing_abi_values_are_grouped_enums_with_stable_integer_values) {
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
    EXPECT_EQ(reply.kind, 3);
}

TEST(Core, the_generated_signing_abi_links_and_returns_owned_errors) {
    C2paSmBuildSession *session = nullptr;
    C2paSmError *error = nullptr;
    const int code = c2pa_sm_build_session_new("{}", "image/jpeg", "es256", nullptr, 0,
                                              &session, &error);
    EXPECT_EQ(code, C2PA_SM_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(session == nullptr);
    EXPECT_TRUE(error != nullptr);
    EXPECT_EQ(c2pa_sm_error_code(error), code);
    EXPECT_TRUE(std::string(c2pa_sm_error_message(error)).size() > 0);
    c2pa_sm_error_free(error);
    EXPECT_EQ(c2pa_sm_build_session_free(nullptr, nullptr), C2PA_SM_OK);
    EXPECT_EQ(c2pa_sm_sign_report_free(nullptr, nullptr), C2PA_SM_OK);
}

TEST(Core, signing_settings_keep_certificates_and_definition_as_owned_values) {
    BuildSettings settings;
    EXPECT_EQ(settings.format, "image/jpeg");
    EXPECT_EQ(settings.algorithm, "es256");
    EXPECT_TRUE(settings.certificates.empty());
    settings.definition_json = "{}";
    settings.certificates = {{1, 2}, {3, 4}};
    auto copied = settings;
    settings.definition_json.clear();
    settings.certificates.front().clear();
    EXPECT_EQ(copied.definition_json, "{}");
    EXPECT_EQ(copied.certificates.front(), (std::vector<uint8_t>{1, 2}));
    EXPECT_EQ(copied.certificates.back(), (std::vector<uint8_t>{3, 4}));
}

TEST(Core, signing_requests_identify_streams_and_own_their_payloads) {
    static_assert(std::variant_size_v<BuildRequest> == 5);
    static_assert(!std::is_copy_constructible_v<BuildRequest>);
    std::vector<BuildRequest> requests;
    requests.emplace_back(BuildReadRequest{10, BuildStream::Source, 20, 30});
    requests.emplace_back(BuildLengthRequest{11, BuildStream::Source});
    requests.emplace_back(retained_write_request(12, BuildStream::Output, 40));
    requests.emplace_back(SignRequest{13, "es256", {3, 4}});
    requests.emplace_back(TimestampRequest{14, "https://tsa.example", {5, 6}});
    requests.emplace_back(BuildReadRequest{15, BuildStream::Output, 50, 60});
    requests.emplace_back(BuildLengthRequest{16, BuildStream::Output});
    uint64_t expected_id = 10;
    for (const auto &request : requests) {
        EXPECT_EQ(std::visit([](const auto &pending) { return pending.id; }, request), expected_id);
        ++expected_id;
    }
    const auto copied = std::move(requests);
    EXPECT_TRUE(std::get<BuildReadRequest>(copied[0]).stream == BuildStream::Source);
    EXPECT_EQ(std::get<BuildReadRequest>(copied[0]).start, uint64_t(20));
    EXPECT_EQ(std::get<BuildReadRequest>(copied[0]).len, uint64_t(30));
    EXPECT_TRUE(std::get<BuildReadRequest>(copied[5]).stream == BuildStream::Output);
    EXPECT_TRUE(std::get<BuildLengthRequest>(copied[6]).stream == BuildStream::Output);
    EXPECT_TRUE(std::get<WriteRequest>(copied[2]).stream == BuildStream::Output);
    EXPECT_EQ(std::get<WriteRequest>(copied[2]).offset, uint64_t(40));
    EXPECT_GT(std::get<WriteRequest>(copied[2]).bytes.view().size, size_t{0});
    EXPECT_EQ(std::get<SignRequest>(copied[3]).algorithm, "es256");
    EXPECT_EQ(std::get<SignRequest>(copied[3]).data, (std::vector<uint8_t>{3, 4}));
    EXPECT_EQ(std::get<TimestampRequest>(copied[4]).url, "https://tsa.example");
    EXPECT_EQ(std::get<TimestampRequest>(copied[4]).body, (std::vector<uint8_t>{5, 6}));
}

TEST(Core, signing_replies_and_report_hold_plain_values) {
    static_assert(std::variant_size_v<BuildReply> == 6);
    static_assert(!std::is_copy_constructible_v<BuildReply>);
    BuildReply reply = CompletedRead{};
    EXPECT_TRUE(std::holds_alternative<CompletedRead>(reply));
    reply = Length{42};
    EXPECT_EQ(std::get<Length>(reply).value, uint64_t(42));
    reply = Written{};
    EXPECT_TRUE(std::holds_alternative<Written>(reply));
    reply = Signature{{3, 4}};
    EXPECT_EQ(std::get<Signature>(reply).data, (std::vector<uint8_t>{3, 4}));
    reply = TimestampResponse{{5, 6}};
    EXPECT_EQ(std::get<TimestampResponse>(reply).data, (std::vector<uint8_t>{5, 6}));
    reply = Failed{"signer unavailable"};
    EXPECT_EQ(std::get<Failed>(reply).message, "signer unavailable");
    SignReport report{{7, 8}, {{10, 2}, {30, 4}}};
    auto copied = report;
    report.manifest.clear();
    report.exclusions.clear();
    EXPECT_EQ(copied.manifest, (std::vector<uint8_t>{7, 8}));
    EXPECT_EQ(copied.exclusions.size(), size_t(2));
    EXPECT_EQ(copied.exclusions.front().start, uint64_t(10));
    EXPECT_EQ(copied.exclusions.back().len, uint64_t(4));
}

TEST(Core, a_signed_jpeg_reads_through_the_blocking_driver) {
    MemoryHost host = fixture_host();
    auto reader = read(Session("image/jpeg"), host);
    EXPECT_TRUE(reader.has_value());
    EXPECT_TRUE(reader->json().find("\"validation_state\": \"Valid\"") != std::string::npos);
    EXPECT_TRUE(reader->is_embedded());
    auto label = reader->active_label();
    EXPECT_TRUE(label.has_value());
    EXPECT_TRUE(reader->json().find(*label) != std::string::npos);
}

TEST(Core, a_stream_and_a_file_read_the_same_as_memory) {
    MemoryHost memory = fixture_host();
    const std::string expected = json_of(read(Session("jpg"), memory));
    EXPECT_TRUE(!expected.empty());

    std::ifstream file(C2PA_SM_FIXTURE, std::ios::binary);
    IStreamHost stream(file);
    stream.read(0, 1);  // leave the stream mid-file: the host must seek
    EXPECT_EQ(json_of(read(Session("image/jpeg"), stream)), expected);

    const std::vector<uint8_t> bytes = fixture_bytes();
    std::string raw(bytes.begin(), bytes.end());
    std::istringstream in(raw);
    IStreamHost from_string(in);
    EXPECT_EQ(json_of(read(Session("image/jpeg"), from_string)), expected);

    // FileHost does not pin the clock, so only check that it reads at all
    // (the certificate chain's validity is a function of the wall clock).
    FileHost path_host(C2PA_SM_FIXTURE);
    EXPECT_EQ(path_host.length(), fixture_bytes().size());
    EXPECT_EQ(path_host.read(0, 2), (std::vector<uint8_t>{0xff, 0xd8}));
    EXPECT_TRUE(read(Session("image/jpeg"), path_host).has_value());
}

TEST(Core, an_asset_with_no_manifest_store_is_nullopt_not_an_error) {
    MemoryHost host(std::vector<uint8_t>{0xff, 0xd8, 0xff, 0xd9});
    EXPECT_TRUE(!read(Session("image/jpeg"), host).has_value());
}

TEST(Core, errors_are_values_with_a_code_and_a_name) {
    EXPECT_THROW_CODE(Session("image/png"), ErrorCode::UnsupportedType);
    try {
        Session session("image/png");
    } catch (const Exception &e) {
        EXPECT_EQ(e.name(), "C2pa(UnsupportedType)");
        EXPECT_EQ(std::string(e.what()), "type is unsupported");
    }
    EXPECT_THROW_CODE(Session("image/jpeg", std::string("{not json")), ErrorCode::InvalidArgument);
    Session ok("image/jpeg", std::string("{}"));  // valid settings are accepted
}

TEST(Core, a_host_that_fails_a_read_fails_the_read_not_the_process) {
    struct Broken : MemoryHost {
        Broken() : MemoryHost(fixture_bytes(), kNow) {}
        std::vector<uint8_t> read(uint64_t, uint64_t) override { throw std::runtime_error("disk on fire"); }
    } host;
    EXPECT_THROW_CODE(read(Session("image/jpeg"), host), ErrorCode::Read);

    // A stream that is too short fails the same way.
    std::istringstream truncated(std::string(100, 'x'));
    IStreamHost short_stream(truncated);
    EXPECT_THROW_CODE(read(Session("image/jpeg"), short_stream), ErrorCode::Read);
    bool out_of_range = false;
    try {
        MemoryHost({1, 2, 3}).read(2, 5);
    } catch (const std::out_of_range &) {
        out_of_range = true;
    }
    EXPECT_TRUE(out_of_range);
}

TEST(Core, a_stream_shorter_than_asked_is_a_host_failure) {
    std::istringstream in(std::string(10, 'x'));
    IStreamHost host(in);
    EXPECT_EQ(host.length(), uint64_t(10));
    EXPECT_EQ(host.read(5, 5).size(), size_t(5));
    bool threw = false;
    try {
        host.read(5, 50);
    } catch (const std::runtime_error &) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

TEST(Core, a_stream_that_cannot_seek_has_no_length_rather_than_a_huge_one) {
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
    EXPECT_TRUE(threw);
    // ...and a whole read against it fails as a host failure, not a hang.
    EXPECT_THROW_CODE(read(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(Core, a_failed_clock_and_a_missing_file_are_host_failures_too) {
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
    EXPECT_TRUE(threw);
    threw = false;
    try {
        missing.read(0, 1);
    } catch (const std::runtime_error &) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

TEST(Core, answer_turns_every_request_kind_into_a_reply_and_exceptions_into_failed) {
    MemoryHost host = fixture_host();
    EXPECT_TRUE(std::holds_alternative<Bytes>(answer(host, ReadRequest{1, 0, 4})));
    EXPECT_TRUE(std::holds_alternative<Length>(answer(host, LengthRequest{2})));
    EXPECT_EQ(std::get<Time>(answer(host, TimeRequest{3})).seconds, kNow);
    // No network by default: a failure, which the engine treats as fail-open.
    auto ocsp = answer(host, OcspRequest{4, "http://ocsp.example/", {1, 2}});
    EXPECT_TRUE(std::holds_alternative<Failed>(ocsp));

    struct Responder : MemoryHost {
        Responder() : MemoryHost({}) {}
        std::vector<uint8_t> ocsp(const std::string &url, const std::vector<uint8_t> &body) override {
            return url == "http://ocsp.example/" ? body : std::vector<uint8_t>{};
        }
    } responder;
    auto answered = answer(responder, OcspRequest{5, "http://ocsp.example/", {7, 8}});
    EXPECT_EQ(std::get<Ocsp>(answered).data, (std::vector<uint8_t>{7, 8}));

    // Even a thrown non-exception is a Failed, not a crash.
    struct Weird : MemoryHost {
        Weird() : MemoryHost({}) {}
        uint64_t length() override { throw 42; }
    } weird;
    EXPECT_TRUE(std::holds_alternative<Failed>(answer(weird, LengthRequest{6})));
}

TEST(Core, every_kind_of_request_the_library_reports_is_described_as_plain_values) {
    // The engine never issues an OCSP request for this repository's
    // fixtures, so the description is checked on hand-built C structs.
    C2paSmRequest r{};
    r.id = 7;
    r.kind = C2PA_SM_REQUEST_READ;
    r.start = 5;
    r.len = 9;
    auto read_request = std::get<ReadRequest>(detail::describe(r));
    EXPECT_EQ(read_request.id, uint64_t(7));
    EXPECT_EQ(read_request.start, uint64_t(5));
    EXPECT_EQ(read_request.len, uint64_t(9));

    r.kind = C2PA_SM_REQUEST_LENGTH;
    EXPECT_EQ(std::get<LengthRequest>(detail::describe(r)).id, uint64_t(7));
    r.kind = C2PA_SM_REQUEST_TIME;
    EXPECT_EQ(std::get<TimeRequest>(detail::describe(r)).id, uint64_t(7));

    const char url[] = "http://ocsp.example/";
    const uint8_t body[] = {1, 2, 3};
    r.kind = C2PA_SM_REQUEST_OCSP;
    r.url = url;
    r.url_len = sizeof(url) - 1;
    r.body = body;
    r.body_len = sizeof(body);
    auto ocsp = std::get<OcspRequest>(detail::describe(r));
    EXPECT_EQ(ocsp.url, "http://ocsp.example/");
    EXPECT_EQ(ocsp.body, (std::vector<uint8_t>{1, 2, 3}));
    EXPECT_EQ(request_id(Request(ocsp)), uint64_t(7));
}

TEST(Core, small_helpers_handle_the_cases_the_engine_does_not_produce) {
    // A null string from the library reads as absent / empty.
    EXPECT_TRUE(!detail::take_optional_string(nullptr).has_value());
    EXPECT_EQ(detail::take_string(nullptr), "");

    // A driver with nothing to wait on reports it rather than hanging.
    detail::require_progress(true);
    EXPECT_THROW_CODE(detail::require_progress(false), ErrorCode::Read);

    // The default clock is the system clock; a pinned one is not.
    MemoryHost unpinned({});
    EXPECT_TRUE(unpinned.now() > 1'700'000'000);
    EXPECT_EQ(MemoryHost({}, 5).now(), int64_t(5));
    bool threw = false;
    try {
        MemoryHost({1}).read(9, 1);  // start past the end, as opposed to len
    } catch (const std::out_of_range &) {
        threw = true;
    }
    EXPECT_TRUE(threw);
}

TEST(Core, misusing_the_protocol_is_an_error_and_leaves_the_session_usable) {
    Session session("image/jpeg");
    Step step = session.advance();
    EXPECT_TRUE(!step.done);
    EXPECT_TRUE(!step.requests.empty());

    EXPECT_THROW_CODE(session.fulfill(~0ull, Time{0}), ErrorCode::InvalidArgument);
    // Every reply kind is accepted for marshalling, and refused by id.
    EXPECT_THROW_CODE(session.fulfill(~0ull, Ocsp{{1, 2}}), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(session.fulfill(~0ull, Length{1}), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(session.fulfill(~0ull, Bytes{{1}}), ErrorCode::InvalidArgument);
    EXPECT_THROW_CODE(session.fulfill(~0ull, Failed{"x"}), ErrorCode::InvalidArgument);
    try {
        session.fulfill(~0ull, Time{0});
    } catch (const Exception &e) {
        // The message really came from the library, not a placeholder.
        EXPECT_TRUE(std::string(e.what()).find("no outstanding request") != std::string::npos);
        EXPECT_TRUE(e.name().rfind("C2pa(BadParam(", 0) == 0);
    }
    // The wrong kind of reply for the request: a clock reading for a read.
    EXPECT_THROW_CODE(session.fulfill(request_id(step.requests[0]), Time{0}), ErrorCode::Read);
}

TEST(Core, the_request_ids_in_one_step_are_distinct_and_replies_may_come_in_any_order) {
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
    EXPECT_TRUE(reversed_at_least_once);
    auto reader = std::move(session).finish();
    MemoryHost again = fixture_host();
    EXPECT_EQ(json_of(reader), json_of(read(Session("image/jpeg"), again)));
}

TEST(Core, a_pool_runs_the_engines_requests_concurrently_and_gets_the_same_answer) {
    MemoryHost reference = fixture_host();
    const std::string expected = json_of(read(Session("image/jpeg"), reference));

    SlowHost slow(std::chrono::milliseconds(10));
    {
        SimpleThreadPool pool(8);
        PooledHost host(slow, pool);
        EXPECT_EQ(json_of(read_parallel(Session("image/jpeg"), host)), expected);
    }
    EXPECT_TRUE(slow.reads() > 1);
    EXPECT_TRUE(slow.max_in_flight() > 1);  // the point of the exercise

    // The same engine, the same host, one request at a time: same answer,
    // and never more than one in flight. Concurrency is the host's choice.
    SlowHost serial(std::chrono::milliseconds(0));
    EXPECT_EQ(json_of(read(Session("image/jpeg"), serial)), expected);
    EXPECT_EQ(serial.max_in_flight(), size_t(1));
    EXPECT_EQ(serial.reads(), slow.reads());
}

TEST(Core, a_read_can_be_a_future_and_many_can_run_at_once) {
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
        EXPECT_EQ(json_of(future.get()), expected);
    }
}

TEST(Core, one_thread_can_multiplex_many_reads_with_no_threads_at_all) {
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
            EXPECT_TRUE(hosts[i]->parked() > 0);
            hosts[i]->complete(hosts[i]->parked() - 1);
            if (readings[i]->step()) {
                finished[i] = true;
                --remaining;
            }
        }
    }
    EXPECT_TRUE(rounds > 1);
    for (int i = 0; i < kReads; ++i) {
        EXPECT_EQ(json_of(std::move(*readings[i]).finish()), expected);
        EXPECT_TRUE(readings[i]->max_in_flight() >= 1);
        EXPECT_TRUE(readings[i]->started() >= readings[i]->max_in_flight());
        EXPECT_EQ(readings[i]->in_flight(), size_t(0));
    }
}

TEST(Core, cancelling_a_read_with_requests_in_flight_is_safe) {
    MemoryHost backing = fixture_host();
    ManualHost host(backing);
    auto reading = std::make_unique<Reading>(Session("image/jpeg"), host);
    EXPECT_TRUE(!reading->step());
    EXPECT_TRUE(host.parked() > 0);

    // Destroying the read *is* cancelling it. The host's work is already
    // started; its completions arrive afterward, and must land nowhere
    // harmful (run under ASan in CI).
    reading.reset();
    while (host.parked() > 0) {
        host.complete(0);
    }
}

TEST(Core, a_host_whose_start_throws_fails_that_request_not_the_driver) {
    struct Throwing : AsyncHost {
        void start(const Request &, Completion) override { throw std::runtime_error("no"); }
    } host;
    EXPECT_THROW_CODE(read_parallel(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(Core, a_host_that_throws_something_that_is_not_an_exception_fails_the_request_too) {
    struct Throwing : AsyncHost {
        void start(const Request &, Completion) override { throw 42; }
    } host;
    EXPECT_THROW_CODE(read_parallel(Session("image/jpeg"), host), ErrorCode::Read);
}

TEST(Core, a_session_moves_between_threads_between_calls) {
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
    EXPECT_TRUE(reader.has_value());

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
    EXPECT_EQ(agree.load(), 8);
}

TEST(Core, a_moved_from_session_and_reader_are_inert_and_move_assignment_works) {
    MemoryHost host = fixture_host();
    Session a("image/jpeg");
    Session b("jpg");
    a = std::move(b);  // frees a's old read, adopts b's
    auto first = read(std::move(a), host);
    EXPECT_TRUE(first.has_value());

    MemoryHost again = fixture_host();
    auto second = read(Session("image/jpeg"), again);
    first = std::move(second);
    EXPECT_TRUE(first.has_value());
}

TEST(Core, the_wait_registers_a_waker_only_when_nothing_has_arrived) {
    Mailbox mailbox;
    int woke = 0;
    EXPECT_TRUE(mailbox.set_waker([&] { ++woke; }));
    mailbox.post(1, Time{0});
    EXPECT_EQ(woke, 1);
    EXPECT_TRUE(!mailbox.set_waker([&] { ++woke; }));  // a reply is already waiting
    EXPECT_EQ(mailbox.drain().size(), size_t(1));

    EXPECT_TRUE(mailbox.set_waker([&] { ++woke; }));
    mailbox.clear_waker();
    mailbox.post(2, Time{0});
    EXPECT_EQ(woke, 1);  // cleared: never called
    mailbox.wait();     // returns at once: a reply is waiting
}
