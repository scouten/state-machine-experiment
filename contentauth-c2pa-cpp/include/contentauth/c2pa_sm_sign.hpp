#ifndef CONTENTAUTH_C2PA_SM_SIGN_HPP
#define CONTENTAUTH_C2PA_SM_SIGN_HPP

#include "c2pa_sm.hpp"
#include "contentauth_c2pa_c_api.h"

#include <functional>

namespace c2pa::sm {

/// Inputs copied by BuildSession; no private key crosses the ABI.
struct BuildSettings {
    std::string definition_json;
    std::string format = "image/jpeg";
    std::string algorithm = "es256";
    std::vector<std::vector<uint8_t>> certificates;
};

/// Separate host-owned assets; source and output must not alias.
enum class BuildStream { Source, Output };

/// A Rust-owned, exclusive initialized read destination.
struct MutableBytes {
    uint8_t *data;
    size_t size;
};

/// A read-only byte view; the caller must retain its owning buffer during I/O.
struct ConstBytes {
    const uint8_t *data;
    size_t size;
};

/// Move-only immutable write storage, independent of its original session.
class WriteBuffer {
public:
    WriteBuffer() = default;
    WriteBuffer(C2paSmBuildSession *session, uint64_t id);
    ~WriteBuffer();
    WriteBuffer(WriteBuffer &&other) noexcept;
    WriteBuffer &operator=(WriteBuffer &&other) noexcept;
    WriteBuffer(const WriteBuffer &) = delete;
    WriteBuffer &operator=(const WriteBuffer &) = delete;
    ConstBytes view() const;
private:
    C2paSmWriteBuffer *raw_ = nullptr;
    ConstBytes bytes_{nullptr, 0};
};

/// Move-only sealed storage, freed independently of its original session.
class CompletedRead {
public:
    CompletedRead() = default;
    ~CompletedRead();
    CompletedRead(CompletedRead &&other) noexcept;
    CompletedRead &operator=(CompletedRead &&other) noexcept;
    CompletedRead(const CompletedRead &) = delete;
    CompletedRead &operator=(const CompletedRead &) = delete;
private:
    friend class ReadBuffer;
    friend class BuildSession;
    C2paSmCompletedRead *raw_ = nullptr;
};

/// Independent writable lease. Stop all I/O before sealing or destroying it.
class ReadBuffer {
public:
    ReadBuffer() = default;
    ReadBuffer(C2paSmBuildSession *session, uint64_t id);
    ~ReadBuffer();
    ReadBuffer(ReadBuffer &&other) noexcept;
    ReadBuffer &operator=(ReadBuffer &&other) noexcept;
    ReadBuffer(const ReadBuffer &) = delete;
    ReadBuffer &operator=(const ReadBuffer &) = delete;
    MutableBytes writable() const;
    CompletedRead seal(size_t bytes_read) &&;
private:
    C2paSmReadBuffer *raw_ = nullptr;
    MutableBytes bytes_{nullptr, 0};
};

/// Read exactly len bytes at start into destination; answer with CompletedRead.
struct BuildReadRequest {
    uint64_t id;
    BuildStream stream;
    uint64_t start;
    uint64_t len;
    ReadBuffer destination{};
};

/// Report the selected stream's length; answer with Length.
struct BuildLengthRequest {
    uint64_t id;
    BuildStream stream;
};

/// Write every byte at offset; answer with Written after reads can see it.
struct WriteRequest {
    uint64_t id;
    BuildStream stream;
    uint64_t offset;
    WriteBuffer bytes;
};

/// Sign the complete COSE Sig_structure, not a precomputed digest.
struct SignRequest {
    uint64_t id;
    std::string algorithm;
    std::vector<uint8_t> data;
};

/// POST body to url as application/timestamp-query; return the raw response.
struct TimestampRequest {
    uint64_t id;
    std::string url;
    std::vector<uint8_t> body;
};

using BuildRequest =
    std::variant<BuildReadRequest, BuildLengthRequest, WriteRequest, SignRequest, TimestampRequest>;

/// The complete write is visible to subsequent output reads.
struct Written {};

/// ES256 uses the 64-byte raw r || s representation, not DER.
struct Signature {
    std::vector<uint8_t> data;
};

/// The unmodified DER TimeStampResp, not just its TimeStampToken.
struct TimestampResponse {
    std::vector<uint8_t> data;
};

using BuildReply = std::variant<CompletedRead, Length, Written, Signature, TimestampResponse, Failed>;

/// A range omitted from the output asset's hard-binding hash.
struct Exclusion {
    uint64_t start;
    uint64_t len;
};

/// The asset has already been written to the host's output stream.
struct SignReport {
    std::vector<uint8_t> manifest;
    std::vector<Exclusion> exclusions;
};

/// Newly issued, owned requests; an empty batch is not completion.
struct BuildStep {
    bool done = false;
    std::vector<BuildRequest> requests;
};

/// The ID to quote when answering a build request.
uint64_t request_id(const BuildRequest &request);

namespace detail {

struct BuildSessionDeleter {
    void operator()(C2paSmBuildSession *session) const noexcept;
};

struct SignReportDeleter {
    void operator()(C2paSmSignReport *report) const noexcept;
};

std::vector<uint8_t> build_bytes(C2paSmBuffer buffer);
std::string build_string(C2paSmBuffer buffer);
BuildStream build_stream(int stream);
BuildRequest describe(C2paSmBuildSession *session, const C2paSmBuildRequest &pending);
void build_range(uint64_t start, uint64_t len, uint64_t limit);

}  // namespace detail

/// A move-only, synchronous sans-I/O build. Destruction cancels the build.
class BuildSession {
public:
    /// Copies settings into Rust; the host keeps its key and all I/O resources.
    explicit BuildSession(const BuildSettings &settings);
    ~BuildSession();

    BuildSession(BuildSession &&) noexcept;
    BuildSession &operator=(BuildSession &&) noexcept;
    BuildSession(const BuildSession &) = delete;
    BuildSession &operator=(const BuildSession &) = delete;

    /// Owns the new request batch, including independent writable read leases.
    BuildStep advance();

    /// Answers any outstanding request; invalid IDs or kinds leave it outstanding.
    void fulfill(uint64_t id, BuildReply &&reply);

    /// Consumes even on error; copies the report before releasing its ABI storage.
    SignReport finish() &&;

private:
    std::unique_ptr<C2paSmBuildSession, detail::BuildSessionDeleter> raw_;
};

/// Host callback: algorithm plus complete signing input; ES256 returns raw r || s.
using BuildSigner = std::function<std::vector<uint8_t>(const std::string &, const std::vector<uint8_t> &)>;
/// Host callback: URL plus DER TimeStampReq, returning the whole DER TimeStampResp.
using BuildTimestamp = std::function<std::vector<uint8_t>(const std::string &, const std::vector<uint8_t> &)>;

/// Blocking host contract. Callbacks and I/O may throw; answer converts them to Failed.
class SyncBuildHost {
public:
    /// Missing callbacks fail only if the corresponding request is issued.
    explicit SyncBuildHost(BuildSigner signer = {}, BuildTimestamp timestamp = {});
    virtual ~SyncBuildHost();
    /// Fills the entire destination or throws; never acknowledges a short read.
    virtual void read_into(BuildStream stream, uint64_t start, MutableBytes destination) = 0;
    /// Reports the selected stream's current length.
    virtual uint64_t length(BuildStream stream) = 0;
    /// Returns only after the entire write is visible to output reads.
    virtual void write(BuildStream stream, uint64_t offset, ConstBytes bytes) = 0;
    /// Calls the host signer without storing or accessing a key.
    virtual std::vector<uint8_t> sign(const std::string &algorithm, const std::vector<uint8_t> &data);
    /// Calls the host TSA transport; no implicit networking or fallback.
    virtual std::vector<uint8_t> timestamp(const std::string &url, const std::vector<uint8_t> &body);
private:
    BuildSigner signer_;
    BuildTimestamp timestamp_;
};

/// Answers one owned request, converting host exceptions and short reads to Failed.
BuildReply answer(SyncBuildHost &host, BuildRequest &request);
inline BuildReply answer(SyncBuildHost &host, BuildRequest &&request) {
    return answer(host, request);
}

/// Drives a build on the calling thread; a pending empty batch is never completion.
SignReport build_and_sign(BuildSession session, SyncBuildHost &host);

/// Independent owned source and initially empty, readable output buffers.
class MemoryBuildHost : public SyncBuildHost {
public:
    /// Copies or moves source bytes; output never aliases the caller's asset.
    explicit MemoryBuildHost(std::vector<uint8_t> source, BuildSigner signer = {}, BuildTimestamp timestamp = {});
    /// The written asset, also available after a failed build for inspection.
    const std::vector<uint8_t> &output() const noexcept;
    void read_into(BuildStream stream, uint64_t start, MutableBytes destination) override;
    uint64_t length(BuildStream stream) override;
    void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override;
private:
    std::vector<uint8_t> source_;
    std::vector<uint8_t> output_;
};

/// Seekable streams; output must be empty, distinct, readable and writable.
class IOStreamBuildHost : public SyncBuildHost {
public:
    /// Streams must outlive the host; failures may leave partial output.
    IOStreamBuildHost(std::istream &source, std::iostream &output, BuildSigner signer = {}, BuildTimestamp timestamp = {});
    void read_into(BuildStream stream, uint64_t start, MutableBytes destination) override;
    uint64_t length(BuildStream stream) override;
    void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override;
private:
    std::istream &source_;
    std::iostream &output_;
};

#if defined(__unix__) || defined(__APPLE__)
/// POSIX file host: exclusive mode-0600 temporary, unlinked unless published on success.
/// Published files retain mode 0600, not the source or destination permissions.
class FileBuildHost : public SyncBuildHost {
public:
    /// Opens source read-only and creates an unpredictable temporary beside destination.
    FileBuildHost(const std::filesystem::path &source, const std::filesystem::path &destination,
                  BuildSigner signer = {}, BuildTimestamp timestamp = {});
    ~FileBuildHost() override;
    FileBuildHost(const FileBuildHost &) = delete;
    FileBuildHost &operator=(const FileBuildHost &) = delete;
    void read_into(BuildStream stream, uint64_t start, MutableBytes destination) override;
    uint64_t length(BuildStream stream) override;
    void write(BuildStream stream, uint64_t offset, ConstBytes bytes) override;
private:
    friend SignReport build_and_sign_file(const BuildSettings &, const std::filesystem::path &,
                                          const std::filesystem::path &, BuildSigner, BuildTimestamp);
    int descriptor(BuildStream stream) const;
    void publish();
    std::filesystem::path destination_;
    std::string temporary_;
    int source_ = -1;
    int output_ = -1;
    bool published_ = false;
};

/// POSIX atomic replacement; any failure preserves an existing destination.
/// Output is mode 0600. File contents are synced, but not the parent directory:
/// replacement is atomic, not guaranteed durable across a system crash.
SignReport build_and_sign_file(const BuildSettings &settings, const std::filesystem::path &source,
                                      const std::filesystem::path &destination, BuildSigner signer,
                                      BuildTimestamp timestamp = {});
#endif

}  // namespace c2pa::sm

#endif