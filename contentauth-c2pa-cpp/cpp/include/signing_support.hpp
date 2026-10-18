#pragma once

#include "contentauth/c2pa_sm_sign_async.hpp"
#include "fixtures.hpp"
#include "../tests/support.hpp"
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace support {

inline std::vector<uint8_t> signing_certificate() {
    std::ifstream input(signing_cert_path, std::ios::binary);
    if (!input) throw std::runtime_error("missing signing certificate");
    return {std::istreambuf_iterator<char>(input), {}};
}

inline c2pa::sm::BuildSettings signing_settings(bool timestamp = false) {
    c2pa::sm::BuildSettings settings;
    settings.definition_json = signing_definition;
    settings.certificates = {signing_certificate()};
    if (timestamp) settings.definition_json.insert(1, "\"tsa_url\":\"https://tsa.example/\",");
    return settings;
}

inline std::vector<uint8_t> fixture_sign(const std::string &algorithm, const std::vector<uint8_t> &data) {
    if (algorithm != "es256") throw std::runtime_error("unexpected signing algorithm");
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_file(signing_key_path, "r"), BIO_free);
    if (!input) throw std::runtime_error("missing signing key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t size = 0;
    if (!key || !context || EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1 ||
        EVP_DigestSign(context.get(), nullptr, &size, data.data(), data.size()) != 1)
        throw std::runtime_error("cannot initialize fixture signer");
    std::vector<uint8_t> der(size);
    if (EVP_DigestSign(context.get(), der.data(), &size, data.data(), data.size()) != 1)
        throw std::runtime_error("fixture signing failed");
    const auto *cursor = der.data();
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> signature(
        d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(size)), ECDSA_SIG_free);
    if (!signature) throw std::runtime_error("invalid fixture signature");
    const BIGNUM *first = nullptr;
    const BIGNUM *second = nullptr;
    ECDSA_SIG_get0(signature.get(), &first, &second);
    std::vector<uint8_t> raw(64);
    if (BN_bn2binpad(first, raw.data(), 32) != 32 || BN_bn2binpad(second, raw.data() + 32, 32) != 32)
        throw std::runtime_error("fixture signature conversion failed");
    return raw;
}

inline std::string signing_trust_settings() {
    const auto certificate = signing_certificate();
    std::string base64(4 * ((certificate.size() + 2) / 3), '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(base64.data()), certificate.data(),
                    static_cast<int>(certificate.size()));
    return "{\"trust\":{\"trust_anchors\":\"-----BEGIN CERTIFICATE-----\\n" +
        base64 + "\\n-----END CERTIFICATE-----\"}}";
}

inline std::string trusted_signing_json(const std::vector<uint8_t> &bytes) {
    c2pa::sm::MemoryHost host(bytes, kNow);
    return json_of(read(c2pa::sm::Session("image/jpeg", signing_trust_settings()), host));
}

class ManualBuildHost : public c2pa::sm::AsyncBuildHost {
public:
    c2pa::sm::MemoryBuildHost backing{fixture_bytes(), fixture_sign};
    std::vector<std::pair<c2pa::sm::BuildRequest, c2pa::sm::BuildCompletion>> pending;

    void start(c2pa::sm::BuildRequest request, c2pa::sm::BuildCompletion done) override {
        pending.emplace_back(std::move(request), std::move(done));
    }

    void deliver() {
        auto batch = std::move(pending);
        pending.clear();
        for (auto item = batch.rbegin(); item != batch.rend(); ++item)
            item->second(answer(backing, item->first));
    }
};

}  // namespace support