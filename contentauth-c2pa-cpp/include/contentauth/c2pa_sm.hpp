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

/// @file c2pa_sm.hpp
/// @brief Core of the sans-I/O C++ binding: `Session`, `Reader`, the request
///        and reply vocabulary, and the simplest (blocking) driver.
///
/// C++17, header-only over `contentauth_c2pa_sm.h`. See the directory's
/// README.md for how this differs from c2pa-cpp and why.
///
/// The asynchronous drivers are separate headers, so that including this one
/// costs no threads and, for C++17 users, no coroutines:
///   - `c2pa_sm_async.hpp` (C++17): callbacks, a thread pool, `std::future`.
///   - `c2pa_sm_coro.hpp`  (C++20): `co_await`.

#ifndef CONTENTAUTH_C2PA_SM_HPP
#define CONTENTAUTH_C2PA_SM_HPP

#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <istream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "contentauth_c2pa_sm.h"

namespace c2pa::sm {

/// @brief Why an operation failed. Mirrors `C2PA_SM_ERR_*`.
enum class ErrorCode : int {
    InvalidArgument = C2PA_SM_ERR_INVALID_ARGUMENT,
    UnsupportedType = C2PA_SM_ERR_UNSUPPORTED_TYPE,
    NotFound = C2PA_SM_ERR_NOT_FOUND,
    Read = C2PA_SM_ERR_READ,
    Panic = C2PA_SM_ERR_PANIC,
};

/// @brief The one exception type, like c2pa-cpp's `C2paException` — but
///        carrying its code and name *by value*, captured at the failing
///        call rather than fetched afterward from thread-local state.
///
/// That matters here: a session may be advanced on a different thread
/// each time (a coroutine resumed by whichever thread completed a read), so
/// "the last error on this thread" would be the wrong thread's.
class Exception : public std::runtime_error {
public:
    Exception(ErrorCode code, std::string name, const std::string &message)
        : std::runtime_error(message), code_(code), name_(std::move(name)) {}

    /// @brief The error category, for programmatic handling.
    ErrorCode code() const noexcept { return code_; }

    /// @brief c2pa-rs's `Debug` spelling, e.g. `C2pa(UnsupportedType)` — the
    ///        string c2pa-wasm and c2pa-node expose as an error's name.
    const std::string &name() const noexcept { return name_; }

private:
    ErrorCode code_;
    std::string name_;
};

namespace detail {

// A null `error` (which the library never returns with a failing status) reads
// as InvalidArgument with an empty message, per the ABI.
[[noreturn]] inline void throw_error(C2paSmError *error) {
    Exception ex(static_cast<ErrorCode>(c2pa_sm_error_code(error)), c2pa_sm_error_name(error),
                 c2pa_sm_error_message(error));
    c2pa_sm_error_free(error);
    throw ex;
}

inline void check(int status, C2paSmError *error) {
    if (status != C2PA_SM_OK) {
        throw_error(error);
    }
}

struct SessionDeleter {
    void operator()(C2paSmSession *s) const noexcept { c2pa_sm_session_free(s); }
};
struct ReaderDeleter {
    void operator()(C2paSmReader *r) const noexcept { c2pa_sm_reader_free(r); }
};

/// Takes ownership of an optional string returned by the library.
inline std::optional<std::string> take_optional_string(char *s) {
    std::optional<std::string> out;
    if (s != nullptr) {
        out = s;
    }
    c2pa_sm_string_free(s);
    return out;
}

/// Takes ownership of a string returned by the library (null reads as empty).
inline std::string take_string(char *s) { return take_optional_string(s).value_or(""); }

/// A driver that finds the session neither finished nor waiting on anything
/// it has started would otherwise wait forever; say so instead.
inline void require_progress(bool progressing) {
    if (!progressing) {
        throw Exception(ErrorCode::Read, "Read(Stalled)",
                        "the session is waiting on nothing the host was asked for");
    }
}

}  // namespace detail

/// @name The request/reply vocabulary
/// Plain values; nothing here refers back into the session.
/// @{

/// @brief Read `len` bytes of the asset at `start`. Answer with `Bytes`.
struct ReadRequest {
    uint64_t id;
    uint64_t start;
    uint64_t len;
};
/// @brief Report the asset's length. Answer with `Length`.
struct LengthRequest {
    uint64_t id;
};
/// @brief Report the wall clock. Answer with `Time`.
struct TimeRequest {
    uint64_t id;
};
/// @brief POST `body` to the OCSP responder at `url`. Answer with `Ocsp`.
struct OcspRequest {
    uint64_t id;
    std::string url;
    std::vector<uint8_t> body;
};
using Request = std::variant<ReadRequest, LengthRequest, TimeRequest, OcspRequest>;

/// @brief The bytes of a read.
struct Bytes {
    std::vector<uint8_t> data;
};
/// @brief The asset's length.
struct Length {
    uint64_t value;
};
/// @brief Seconds since the Unix epoch, UTC.
struct Time {
    int64_t seconds;
};
/// @brief An OCSP response body.
struct Ocsp {
    std::vector<uint8_t> data;
};
/// @brief The host could not do it. Valid for any request; the engine
///        decides what that means (fail-open for OCSP, an unevaluated
///        validity window for the clock, an error for an asset read).
struct Failed {
    std::string message;
};
using Reply = std::variant<Bytes, Length, Time, Ocsp, Failed>;

namespace detail {

/// Copies a request out of the session's borrowed storage into plain values.
inline Request describe(const C2paSmRequest &r) {
    switch (r.kind) {
        case C2PA_SM_REQUEST_READ:
            return ReadRequest{r.id, r.start, r.len};
        case C2PA_SM_REQUEST_LENGTH:
            return LengthRequest{r.id};
        case C2PA_SM_REQUEST_TIME:
            return TimeRequest{r.id};
        default:
            return OcspRequest{r.id, std::string(r.url, r.url_len),
                               std::vector<uint8_t>(r.body, r.body + r.body_len)};
    }
}

}  // namespace detail

/// @brief The `id` to quote when answering `request`.
inline uint64_t request_id(const Request &request) {
    return std::visit([](const auto &r) { return r.id; }, request);
}

/// @}

/// @brief A finished read: the validated manifest store, queryable.
///
/// Immutable, so every method is `const` and safe to call from any number
/// of threads at once (no lock, nothing to contend on) — unlike a
/// c2pa-cpp `Reader`, whose native handle is shared with the stream it
/// reads from.
class Reader {
public:
    Reader(Reader &&) noexcept = default;
    Reader &operator=(Reader &&) noexcept = default;
    Reader(const Reader &) = delete;
    Reader &operator=(const Reader &) = delete;

    /// @brief The manifest store as c2pa-rs-shaped, pretty-printed JSON.
    std::string json() const { return detail::take_string(c2pa_sm_reader_json(raw_.get())); }

    /// @brief The active manifest's label, if any.
    std::optional<std::string> active_label() const {
        return detail::take_optional_string(c2pa_sm_reader_active_label(raw_.get()));
    }

    /// @brief Whether the manifest store was embedded in the asset.
    bool is_embedded() const { return c2pa_sm_reader_is_embedded(raw_.get()); }

private:
    friend class Session;
    explicit Reader(C2paSmReader *raw) : raw_(raw) {}
    std::unique_ptr<C2paSmReader, detail::ReaderDeleter> raw_;
};

/// @brief What `Session::advance` reports.
struct Step {
    /// The read is finished; call `Session::finish`.
    bool done = false;
    /// Requests that are *new* since the last `advance` — possibly none, if
    /// the session is still waiting on requests already reported.
    std::vector<Request> requests;
};

/// @brief A read of one asset, driven entirely by its caller.
///
/// Moving a `Session` moves the read; destroying one cancels it. There is no
/// `cancel()` and no progress callback because there is nothing to
/// interrupt: the session holds no thread, no lock and no pointer into the
/// host, so a host that stops driving it has stopped it, and replies still
/// in flight from the host are simply never delivered.
///
/// Like any C++ object it must not be used from two threads at once; unlike
/// one wrapping a native stream, it may freely be *moved to* another thread
/// between calls.
class Session {
public:
    /// @brief Starts a read of an asset of type `format` (a MIME type or bare
    ///        extension), under c2pa-rs settings JSON (none: defaults).
    ///
    /// The settings are copied here and then forgotten: there is no
    /// `Context` object to keep alive, and so none to dangle.
    ///
    /// @throws Exception `UnsupportedType`, or `InvalidArgument` for bad
    ///         settings; before any request is made.
    explicit Session(const std::string &format,
                     const std::optional<std::string> &settings_json = std::nullopt) {
        C2paSmSession *raw = nullptr;
        C2paSmError *error = nullptr;
        int status = c2pa_sm_session_new(format.c_str(),
                                         settings_json ? settings_json->c_str() : nullptr, &raw,
                                         &error);
        detail::check(status, error);
        raw_.reset(raw);
    }

    Session(Session &&) noexcept = default;
    Session &operator=(Session &&) noexcept = default;
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    /// @brief Runs the engine as far as it can go without the host: one
    ///        bounded slice of parsing or hashing.
    Step advance() {
        int done = 0;
        C2paSmError *error = nullptr;
        // Not `check(advance(..., &error), error)`: the order in which a
        // call's arguments are evaluated is unspecified, and `error` must
        // be read *after* the call fills it.
        int status = c2pa_sm_session_advance(raw_.get(), &done, &error);
        detail::check(status, error);

        Step step;
        step.done = done != 0;
        const size_t count = c2pa_sm_session_request_count(raw_.get());
        step.requests.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            C2paSmRequest r{};
            // `i < count`, so this cannot fail.
            (void)c2pa_sm_session_request(raw_.get(), i, &r);
            step.requests.push_back(detail::describe(r));
        }
        return step;
    }

    /// @brief Reports the outcome of one request. Replies may arrive in any
    ///        order and any subset between calls to `advance`.
    /// @throws Exception `InvalidArgument` if the id was never issued, was
    ///         already answered, or the reply is the wrong kind for it.
    ///         The session stays usable.
    void fulfill(uint64_t id, const Reply &reply) {
        C2paSmReply r{};
        r.id = id;
        std::visit(
            [&r](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, Bytes>) {
                    r.kind = C2PA_SM_REPLY_BYTES;
                    r.data = v.data.data();
                    r.data_len = v.data.size();
                } else if constexpr (std::is_same_v<T, Length>) {
                    r.kind = C2PA_SM_REPLY_LENGTH;
                    r.value = static_cast<int64_t>(v.value);
                } else if constexpr (std::is_same_v<T, Time>) {
                    r.kind = C2PA_SM_REPLY_TIME;
                    r.value = v.seconds;
                } else if constexpr (std::is_same_v<T, Ocsp>) {
                    r.kind = C2PA_SM_REPLY_OCSP;
                    r.data = v.data.data();
                    r.data_len = v.data.size();
                } else {
                    r.kind = C2PA_SM_REPLY_FAILED;
                    r.data = reinterpret_cast<const uint8_t *>(v.message.data());
                    r.data_len = v.message.size();
                }
            },
            reply);
        C2paSmError *error = nullptr;
        int status = c2pa_sm_session_fulfill(raw_.get(), &r, &error);
        detail::check(status, error);
    }

    /// @brief Consumes the finished session.
    /// @return The reader, or `std::nullopt` if the asset carries no
    ///         manifest store — as c2pa-cpp's `Reader::from_asset`.
    /// @throws Exception if the read failed.
    std::optional<Reader> finish() && {
        C2paSmReader *reader = nullptr;
        C2paSmError *error = nullptr;
        // Consumed whether or not this succeeds.
        int status = c2pa_sm_session_finish(raw_.release(), &reader, &error);
        detail::check(status, error);
        if (reader == nullptr) {
            return std::nullopt;
        }
        return Reader(reader);
    }

private:
    std::unique_ptr<C2paSmSession, detail::SessionDeleter> raw_;
};

/// @brief The host's side of a read, for the simple blocking drivers: one
///        ordinary synchronous function per kind of request.
///
/// Every method may throw; the driver turns that into a `Failed` reply, so
/// the *engine* decides what the failure means (fail-open for OCSP, an
/// error for an asset read) rather than each host reinventing it.
///
/// A host handed to the parallel drivers in `c2pa_sm_async.hpp` is called
/// from several threads at once, and must be safe for that.
class SyncHost {
public:
    virtual ~SyncHost() = default;
    virtual std::vector<uint8_t> read(uint64_t start, uint64_t len) = 0;
    virtual uint64_t length() = 0;
    /// @brief The wall clock. Defaults to the system clock; override to
    ///        pin it (a read is a pure function of the asset and *this*).
    virtual int64_t now() {
        using namespace std::chrono;
        return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    }
    /// @brief An OCSP round trip. Defaults to "no network": the engine
    ///        treats a responder that cannot be reached as fail-open.
    virtual std::vector<uint8_t> ocsp(const std::string &url, const std::vector<uint8_t> &body) {
        (void)url;
        (void)body;
        throw std::runtime_error("no network access");
    }
};

/// @brief Answers one request from a `SyncHost`; an exception becomes `Failed`.
inline Reply answer(SyncHost &host, const Request &request) noexcept {
    try {
        return std::visit(
            [&host](const auto &r) -> Reply {
                using T = std::decay_t<decltype(r)>;
                if constexpr (std::is_same_v<T, ReadRequest>) {
                    return Bytes{host.read(r.start, r.len)};
                } else if constexpr (std::is_same_v<T, LengthRequest>) {
                    return Length{host.length()};
                } else if constexpr (std::is_same_v<T, TimeRequest>) {
                    return Time{host.now()};
                } else {
                    return Ocsp{host.ocsp(r.url, r.body)};
                }
            },
            request);
    } catch (const std::exception &e) {
        return Failed{e.what()};
    } catch (...) {
        return Failed{"unknown host error"};
    }
}

/// @brief Drives `session` to completion on the calling thread, answering
///        each request in turn from `host`. The c2pa-cpp calling
///        convention, in a dozen lines.
inline std::optional<Reader> read(Session session, SyncHost &host) {
    for (;;) {
        Step step = session.advance();
        if (step.done) {
            return std::move(session).finish();
        }
        detail::require_progress(!step.requests.empty());
        for (const Request &request : step.requests) {
            session.fulfill(request_id(request), answer(host, request));
        }
    }
}

/// @brief A `SyncHost` over a seekable `std::istream` — the c2pa-cpp
///        `Reader(format, stream)` shape. Not thread-safe: one stream, one
///        position.
class IStreamHost : public SyncHost {
public:
    explicit IStreamHost(std::istream &stream) : stream_(stream) {}

    std::vector<uint8_t> read(uint64_t start, uint64_t len) override {
        std::vector<uint8_t> out(static_cast<size_t>(len));
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(start));
        stream_.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(len));
        if (static_cast<uint64_t>(stream_.gcount()) != len) {
            throw std::runtime_error("short read");
        }
        return out;
    }

    uint64_t length() override {
        stream_.clear();
        stream_.seekg(0, std::ios::end);
        const std::streampos end = stream_.tellg();
        if (stream_.fail() || end < 0) {
            throw std::runtime_error("cannot determine the length of the stream");
        }
        return static_cast<uint64_t>(end);
    }

private:
    std::istream &stream_;
};

/// @brief A `SyncHost` over a file, opening it afresh for every request so
///        that concurrent requests share no stream position. Thread-safe.
class FileHost : public SyncHost {
public:
    explicit FileHost(std::filesystem::path path) : path_(std::move(path)) {}

    std::vector<uint8_t> read(uint64_t start, uint64_t len) override {
        std::ifstream file(path_, std::ios::binary);
        if (!file) {
            throw std::runtime_error("cannot open " + path_.string());
        }
        return IStreamHost(file).read(start, len);
    }

    uint64_t length() override {
        std::error_code ec;
        auto size = std::filesystem::file_size(path_, ec);
        if (ec) {
            throw std::runtime_error("cannot stat " + path_.string() + ": " + ec.message());
        }
        return size;
    }

private:
    std::filesystem::path path_;
};

/// @brief A `SyncHost` over bytes already in memory. Thread-safe.
class MemoryHost : public SyncHost {
public:
    explicit MemoryHost(std::vector<uint8_t> bytes, std::optional<int64_t> pinned_now = std::nullopt)
        : bytes_(std::move(bytes)), pinned_now_(pinned_now) {}

    std::vector<uint8_t> read(uint64_t start, uint64_t len) override {
        if (start > bytes_.size() || len > bytes_.size() - start) {
            throw std::out_of_range("read past the end of the asset");
        }
        auto first = bytes_.begin() + static_cast<std::ptrdiff_t>(start);
        return std::vector<uint8_t>(first, first + static_cast<std::ptrdiff_t>(len));
    }
    uint64_t length() override { return bytes_.size(); }
    int64_t now() override { return pinned_now_ ? *pinned_now_ : SyncHost::now(); }

private:
    std::vector<uint8_t> bytes_;
    std::optional<int64_t> pinned_now_;
};

}  // namespace c2pa::sm

#endif  // CONTENTAUTH_C2PA_SM_HPP
