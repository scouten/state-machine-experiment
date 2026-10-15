#include "contentauth/c2pa_sm_sign.hpp"

#include <algorithm>
#include <limits>
#include <type_traits>

#if defined(__unix__) || defined(__APPLE__)
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2pa::sm {

uint64_t request_id(const BuildRequest &request) {
    return std::visit([](const auto &pending) { return pending.id; }, request);
}

namespace detail {

void BuildSessionDeleter::operator()(C2paSmBuildSession *session) const noexcept {
    (void)c2pa_sm_build_session_free(session, nullptr);
}

void SignReportDeleter::operator()(C2paSmSignReport *report) const noexcept {
    (void)c2pa_sm_sign_report_free(report, nullptr);
}

std::vector<uint8_t> build_bytes(C2paSmBuffer buffer) {
    if (buffer.len == 0) return {};
    return {buffer.data, buffer.data + buffer.len};
}

std::string build_string(C2paSmBuffer buffer) {
    if (buffer.len == 0) return {};
    return {reinterpret_cast<const char *>(buffer.data), buffer.len};
}

BuildStream build_stream(int stream) {
    if (stream == C2PA_SM_BUILD_SOURCE) return BuildStream::Source;
    if (stream == C2PA_SM_BUILD_OUTPUT) return BuildStream::Output;
    throw std::runtime_error("unknown build stream");
}

BuildRequest describe(const C2paSmBuildRequest &pending) {
    switch (pending.kind) {
        case C2PA_SM_BUILD_REQUEST_READ:
            return BuildReadRequest{pending.id, build_stream(pending.stream), pending.offset,
                                    pending.len};
        case C2PA_SM_BUILD_REQUEST_LENGTH:
            return BuildLengthRequest{pending.id, build_stream(pending.stream)};
        case C2PA_SM_BUILD_REQUEST_WRITE:
            return WriteRequest{pending.id, build_stream(pending.stream), pending.offset,
                                build_bytes(pending.data)};
        case C2PA_SM_BUILD_REQUEST_SIGN:
            return SignRequest{pending.id, build_string(pending.algorithm), build_bytes(pending.data)};
        case C2PA_SM_BUILD_REQUEST_TIMESTAMP:
            return TimestampRequest{pending.id, build_string(pending.url), build_bytes(pending.data)};
        default:
            throw std::runtime_error("unknown build request");
    }
}

void build_range(uint64_t start, uint64_t len, uint64_t limit) {
    if (start > limit || len > limit - start) throw std::runtime_error("build I/O out of bounds");
}

}

BuildSession::BuildSession(const BuildSettings &settings) {
    if (settings.definition_json.find('\0') != std::string::npos ||
        settings.format.find('\0') != std::string::npos ||
        settings.algorithm.find('\0') != std::string::npos) {
        throw Exception(ErrorCode::InvalidArgument, "InvalidArgument", "embedded NUL in settings");
    }
    std::vector<C2paSmBuffer> certificates;
    for (const auto &certificate : settings.certificates) {
        certificates.push_back({certificate.data(), certificate.size()});
    }
    C2paSmBuildSession *session = nullptr;
    C2paSmError *error = nullptr;
    const int result = c2pa_sm_build_session_new(
        settings.definition_json.c_str(), settings.format.c_str(), settings.algorithm.c_str(),
        certificates.data(), certificates.size(), &session, &error);
    raw_.reset(session);
    detail::check(result, error);
}

BuildSession::~BuildSession() = default;
BuildSession::BuildSession(BuildSession &&) noexcept = default;
BuildSession &BuildSession::operator=(BuildSession &&) noexcept = default;

BuildStep BuildSession::advance() {
    BuildStep step;
    int done = 0;
    size_t count = 0;
    C2paSmError *error = nullptr;
    int result = c2pa_sm_build_session_advance(raw_.get(), &done, &count, &error);
    detail::check(result, error);
    step.done = done != 0;
    step.requests.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        C2paSmBuildRequest pending{};
        result = c2pa_sm_build_session_request(raw_.get(), index, &pending, &error);
        detail::check(result, error);
        step.requests.push_back(detail::describe(pending));
    }
    return step;
}

void BuildSession::fulfill(uint64_t id, const BuildReply &reply) {
    C2paSmBuildReply response{};
    response.id = id;
    std::visit([&response](const auto &value) {
        using Value = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Value, Length>) {
            response.kind = C2PA_SM_BUILD_REPLY_LENGTH;
            response.value = value.value;
        } else if constexpr (std::is_same_v<Value, Written>) {
            response.kind = C2PA_SM_BUILD_REPLY_WRITTEN;
        } else if constexpr (std::is_same_v<Value, Failed>) {
            response.kind = C2PA_SM_BUILD_REPLY_FAILED;
            response.data = {reinterpret_cast<const uint8_t *>(value.message.data()),
                             value.message.size()};
        } else {
            if constexpr (std::is_same_v<Value, Bytes>) response.kind = C2PA_SM_BUILD_REPLY_BYTES;
            if constexpr (std::is_same_v<Value, Signature>) response.kind = C2PA_SM_BUILD_REPLY_SIGNATURE;
            if constexpr (std::is_same_v<Value, TimestampResponse>) response.kind = C2PA_SM_BUILD_REPLY_TIMESTAMP;
            response.data = {value.data.data(), value.data.size()};
        }
    }, reply);
    C2paSmError *error = nullptr;
    const int result = c2pa_sm_build_session_fulfill(raw_.get(), &response, &error);
    detail::check(result, error);
}

SignReport BuildSession::finish() && {
    C2paSmSignReport *report = nullptr;
    C2paSmError *error = nullptr;
    const int result = c2pa_sm_build_session_finish(raw_.release(), &report, &error);
    std::unique_ptr<C2paSmSignReport, detail::SignReportDeleter> owned(report);
    detail::check(result, error);
    C2paSmSignReportView view{};
    const int viewed = c2pa_sm_sign_report_view(owned.get(), &view, &error);
    detail::check(viewed, error);
    SignReport copied;
    copied.manifest = detail::build_bytes(view.manifest);
    copied.exclusions.reserve(view.exclusion_count);
    for (size_t index = 0; index < view.exclusion_count; ++index) {
        copied.exclusions.push_back({view.exclusions[index].start, view.exclusions[index].len});
    }
    return copied;
}

SyncBuildHost::SyncBuildHost(BuildSigner signer, BuildTimestamp timestamp)
    : signer_(std::move(signer)), timestamp_(std::move(timestamp)) {}

SyncBuildHost::~SyncBuildHost() = default;

std::vector<uint8_t> SyncBuildHost::sign(const std::string &algorithm, const std::vector<uint8_t> &data) {
    if (!signer_) throw std::runtime_error("no signer configured");
    return signer_(algorithm, data);
}

std::vector<uint8_t> SyncBuildHost::timestamp(const std::string &url, const std::vector<uint8_t> &body) {
    if (!timestamp_) throw std::runtime_error("no timestamp callback configured");
    return timestamp_(url, body);
}

BuildReply answer(SyncBuildHost &host, const BuildRequest &request) {
    try {
        return std::visit([&host](const auto &pending) -> BuildReply {
            using Pending = std::decay_t<decltype(pending)>;
            if constexpr (std::is_same_v<Pending, BuildReadRequest>) {
                auto bytes = host.read(pending.stream, pending.start, pending.len);
                if (bytes.size() != pending.len) throw std::runtime_error("short build read");
                return Bytes{std::move(bytes)};
            } else if constexpr (std::is_same_v<Pending, BuildLengthRequest>) {
                return Length{host.length(pending.stream)};
            } else if constexpr (std::is_same_v<Pending, WriteRequest>) {
                host.write(pending.stream, pending.offset, pending.bytes);
                return Written{};
            } else if constexpr (std::is_same_v<Pending, SignRequest>) {
                return Signature{host.sign(pending.algorithm, pending.data)};
            } else {
                return TimestampResponse{host.timestamp(pending.url, pending.body)};
            }
        }, request);
    } catch (const std::exception &error) {
        return Failed{error.what()};
    } catch (...) {
        return Failed{"unknown build host error"};
    }
}

SignReport build_and_sign(BuildSession session, SyncBuildHost &host) {
    for (;;) {
        auto step = session.advance();
        if (step.done) return std::move(session).finish();
        detail::require_progress(!step.requests.empty());
        for (const auto &pending : step.requests) {
            session.fulfill(request_id(pending), answer(host, pending));
        }
    }
}

MemoryBuildHost::MemoryBuildHost(std::vector<uint8_t> source, BuildSigner signer, BuildTimestamp timestamp)
    : SyncBuildHost(std::move(signer), std::move(timestamp)), source_(std::move(source)) {}

const std::vector<uint8_t> &MemoryBuildHost::output() const noexcept {
    return output_;
}

std::vector<uint8_t> MemoryBuildHost::read(BuildStream stream, uint64_t start, uint64_t len) {
    const auto &bytes = stream == BuildStream::Source ? source_ : output_;
    detail::build_range(start, len, bytes.size());
    return {bytes.begin() + static_cast<size_t>(start), bytes.begin() + static_cast<size_t>(start + len)};
}

uint64_t MemoryBuildHost::length(BuildStream stream) {
    return stream == BuildStream::Source ? source_.size() : output_.size();
}

void MemoryBuildHost::write(BuildStream stream, uint64_t offset, const std::vector<uint8_t> &bytes) {
    if (stream != BuildStream::Output) throw std::runtime_error("source is read-only");
    detail::build_range(offset, bytes.size(), output_.max_size());
    output_.resize(std::max(output_.size(), static_cast<size_t>(offset + bytes.size())));
    std::copy(bytes.begin(), bytes.end(), output_.begin() + static_cast<size_t>(offset));
}

IOStreamBuildHost::IOStreamBuildHost(std::istream &source, std::iostream &output, BuildSigner signer, BuildTimestamp timestamp)
    : SyncBuildHost(std::move(signer), std::move(timestamp)), source_(source), output_(output) {
    if (source.rdbuf() == output.rdbuf()) throw std::runtime_error("build streams alias");
    if (length(BuildStream::Output) != 0) throw std::runtime_error("build output must start empty");
}

std::vector<uint8_t> IOStreamBuildHost::read(BuildStream stream, uint64_t start, uint64_t len) {
    detail::build_range(start, len, length(stream));
    detail::build_range(start, len, static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()));
    detail::build_range(0, len, static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()));
    auto &input = stream == BuildStream::Source ? source_ : output_;
    std::vector<uint8_t> bytes;
    detail::build_range(0, len, bytes.max_size());
    bytes.resize(static_cast<size_t>(len));
    input.seekg(static_cast<std::streamoff>(start));
    input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(len));
    if (!input || static_cast<uint64_t>(input.gcount()) != len) throw std::runtime_error("build stream read failed");
    return bytes;
}

uint64_t IOStreamBuildHost::length(BuildStream stream) {
    auto &input = stream == BuildStream::Source ? source_ : output_;
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (!input || end < 0) throw std::runtime_error("build stream length failed");
    return static_cast<uint64_t>(end);
}

void IOStreamBuildHost::write(BuildStream stream, uint64_t offset, const std::vector<uint8_t> &bytes) {
    if (stream != BuildStream::Output) throw std::runtime_error("source is read-only");
    detail::build_range(offset, bytes.size(), static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()));
    detail::build_range(0, bytes.size(), static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()));
    output_.seekp(static_cast<std::streamoff>(offset));
    output_.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output_.flush();
    if (!output_) throw std::runtime_error("build stream write failed");
}

#if defined(__unix__) || defined(__APPLE__)
FileBuildHost::FileBuildHost(const std::filesystem::path &source, const std::filesystem::path &destination,
                           BuildSigner signer, BuildTimestamp timestamp)
    : SyncBuildHost(std::move(signer), std::move(timestamp)), destination_(destination),
      temporary_(destination.string() + ".XXXXXX") {
    if (source.string().find('\0') != std::string::npos || temporary_.find('\0') != std::string::npos)
        throw std::runtime_error("embedded NUL in build path");
    source_ = ::open(source.c_str(), O_RDONLY);
    if (source_ < 0) throw std::runtime_error("cannot open build source");
    output_ = ::mkstemp(temporary_.data());
    if (output_ < 0) {
        ::close(source_);
        throw std::runtime_error("cannot create build temporary");
    }
}

FileBuildHost::~FileBuildHost() {
    ::close(source_);
    ::close(output_);
    if (!published_) ::unlink(temporary_.c_str());
}

std::vector<uint8_t> FileBuildHost::read(BuildStream stream, uint64_t start, uint64_t len) {
    detail::build_range(start, len, length(stream));
    detail::build_range(start, len, static_cast<uint64_t>(std::numeric_limits<off_t>::max()));
    std::vector<uint8_t> bytes;
    detail::build_range(0, len, bytes.max_size());
    bytes.resize(static_cast<size_t>(len));
    size_t completed = 0;
    while (completed < bytes.size()) {
        const auto count = ::pread(descriptor(stream), bytes.data() + completed,
            std::min(bytes.size() - completed, static_cast<size_t>(std::numeric_limits<ssize_t>::max())),
            static_cast<off_t>(start + completed));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("build file read failed");
        completed += static_cast<size_t>(count);
    }
    return bytes;
}

uint64_t FileBuildHost::length(BuildStream stream) {
    struct stat info{};
    if (::fstat(descriptor(stream), &info) != 0 || info.st_size < 0 || !S_ISREG(info.st_mode))
        throw std::runtime_error("build file length failed");
    return static_cast<uint64_t>(info.st_size);
}

void FileBuildHost::write(BuildStream stream, uint64_t offset, const std::vector<uint8_t> &bytes) {
    if (stream != BuildStream::Output) throw std::runtime_error("source is read-only");
    detail::build_range(offset, bytes.size(), static_cast<uint64_t>(std::numeric_limits<off_t>::max()));
    size_t completed = 0;
    while (completed < bytes.size()) {
        const auto count = ::pwrite(output_, bytes.data() + completed,
            std::min(bytes.size() - completed, static_cast<size_t>(std::numeric_limits<ssize_t>::max())),
            static_cast<off_t>(offset + completed));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("build file write failed");
        completed += static_cast<size_t>(count);
    }
}

int FileBuildHost::descriptor(BuildStream stream) const {
    return stream == BuildStream::Source ? source_ : output_;
}

void FileBuildHost::publish() {
    if (::fsync(output_) != 0 || ::rename(temporary_.c_str(), destination_.c_str()) != 0)
        throw std::runtime_error("cannot publish signed file");
    published_ = true;
}

SignReport build_and_sign_file(const BuildSettings &settings, const std::filesystem::path &source,
                              const std::filesystem::path &destination, BuildSigner signer,
                              BuildTimestamp timestamp) {
    BuildSession session(settings);
    FileBuildHost host(source, destination, std::move(signer), std::move(timestamp));
    auto report = build_and_sign(std::move(session), host);
    host.publish();
    return report;
}
#endif

}