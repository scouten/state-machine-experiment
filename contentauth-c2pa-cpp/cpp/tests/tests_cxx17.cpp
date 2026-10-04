// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The core and the thread-based drivers, built as C++17 on purpose.

#include <sstream>

#include "support.hpp"

using namespace c2pa::sm;
using namespace support;

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
        ThreadPool pool(8);
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
    ThreadPool pool(8);
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
