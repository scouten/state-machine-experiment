#include "contentauth/c2pa_sm_sign.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace {

std::vector<uint8_t> load_bytes(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open input: " + path);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    if (input.bad()) throw std::runtime_error("cannot read input: " + path);
    return bytes;
}

c2pa::sm::BuildSigner load_signer(const std::string &path) {
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_file(path.c_str(), "r"), BIO_free);
    if (!input) throw std::runtime_error("cannot open private key");
    std::shared_ptr<EVP_PKEY> key(PEM_read_bio_PrivateKey(input.get(), nullptr,
        [](char *, int, int, void *) { return 0; }, nullptr), EVP_PKEY_free);
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_EC || EVP_PKEY_bits(key.get()) != 256)
        throw std::runtime_error("expected an unencrypted ES256 PEM private key");
    return [key = std::move(key)](const std::string &algorithm, const std::vector<uint8_t> &data) {
        if (algorithm != "es256") throw std::runtime_error("example supports only ES256");
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        size_t size = 0;
        if (!context || EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1 ||
            EVP_DigestSign(context.get(), nullptr, &size, data.data(), data.size()) != 1)
            throw std::runtime_error("cannot initialize signer");
        std::vector<uint8_t> der(size);
        if (EVP_DigestSign(context.get(), der.data(), &size, data.data(), data.size()) != 1)
            throw std::runtime_error("signing failed");
        const auto *cursor = der.data();
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> signature(
            d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(size)), ECDSA_SIG_free);
        if (!signature) throw std::runtime_error("invalid ECDSA signature");
        const BIGNUM *first = nullptr;
        const BIGNUM *second = nullptr;
        ECDSA_SIG_get0(signature.get(), &first, &second);
        std::vector<uint8_t> raw(64);
        if (BN_bn2binpad(first, raw.data(), 32) != 32 || BN_bn2binpad(second, raw.data() + 32, 32) != 32)
            throw std::runtime_error("cannot encode ES256 signature");
        return raw;
    };
}

std::string trust_settings(const std::vector<uint8_t> &certificate) {
    if (certificate.empty() || certificate.size() > 1024 * 1024)
        throw std::runtime_error("invalid certificate size");
    std::string base64(4 * ((certificate.size() + 2) / 3), '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(base64.data()), certificate.data(),
                    static_cast<int>(certificate.size()));
    return "{\"trust\":{\"trust_anchors\":\"-----BEGIN CERTIFICATE-----\\n" +
        base64 + "\\n-----END CERTIFICATE-----\"}}";
}

}

int main(int argc, char **argv) {
    if (argc != 6 && argc != 7) {
        std::fprintf(stderr, "usage: %s SOURCE OUTPUT DEFINITION.json CERTIFICATE.der KEY.pem [UNIX-TIME]\n", argv[0]);
        return 2;
    }
    try {
        const auto definition = load_bytes(argv[3]);
        c2pa::sm::BuildSettings settings;
        settings.definition_json.assign(definition.begin(), definition.end());
        settings.certificates = {load_bytes(argv[4])};
        const auto reader_settings = trust_settings(settings.certificates.front());
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (argc == 7) {
            size_t consumed = 0;
            now = std::stoll(argv[6], &consumed);
            if (consumed != std::string(argv[6]).size()) throw std::runtime_error("invalid UNIX time");
        }
        const auto report = c2pa::sm::build_and_sign_file(settings, argv[1], argv[2], load_signer(argv[5]));
        if (report.manifest.empty()) throw std::runtime_error("empty signed manifest");
        c2pa::sm::MemoryHost host(load_bytes(argv[2]), now);
        auto reader = c2pa::sm::read(c2pa::sm::Session("image/jpeg", reader_settings), host);
        if (!reader) throw std::runtime_error("signed output has no manifest");
        const auto json = reader->json();
        std::printf("%s\n", json.c_str());
        // Reader exposes validation through pretty-printed JSON; match the root field.
        if (json.find("\n  \"validation_state\": \"Trusted\"") == std::string::npos)
            throw std::runtime_error("signed output did not validate as Trusted");
        return 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 2;
    }
}