#ifndef CONTENTAUTH_C2PA_SM_SIGN_HPP
#define CONTENTAUTH_C2PA_SM_SIGN_HPP

#include "c2pa_sm.hpp"

namespace c2pa::sm {

/// Inputs copied by the future BuildSession; no private key crosses the ABI.
struct BuildSettings {
    std::string definition_json;
    std::string format = "image/jpeg";
    std::string algorithm = "es256";
    std::vector<std::vector<uint8_t>> certificates;
};

/// Separate host-owned assets; source and output must not alias.
enum class BuildStream { Source, Output };

/// Read exactly len bytes at start; answer with Bytes.
struct BuildReadRequest {
    uint64_t id;
    BuildStream stream;
    uint64_t start;
    uint64_t len;
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
    std::vector<uint8_t> bytes;
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

using BuildReply = std::variant<Bytes, Length, Written, Signature, TimestampResponse, Failed>;

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

}  // namespace c2pa::sm

#endif