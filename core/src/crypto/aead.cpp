// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/aead.hpp"

#include "aead_internal.hpp"
#include "backend.hpp"
#include "lume/crypto/random.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <expected>

namespace lume::crypto {

static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == aead_key_size);
static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == aead_nonce_size);
static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == aead_tag_size);
static_assert(aead_max_plaintext_size <= crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);

namespace detail {

namespace {

bool has_valid_sizes(const SecretBytes& key, ByteView nonce)
{
    return key.size() == aead_key_size && nonce.size() == aead_nonce_size;
}

}

Result<Bytes> aead_encrypt(const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView plaintext)
{
    if (!has_valid_sizes(key, nonce) || plaintext.size() > aead_max_plaintext_size) {
        return std::unexpected(Error::invalid_size);
    }
    require_operational();

    Bytes ciphertext(plaintext.size() + aead_tag_size);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &written, pointer_to(plaintext), plaintext.size(), pointer_to(associated_data),
            associated_data.size(), nullptr, nonce.data(), key.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    ciphertext.resize(static_cast<std::size_t>(written));
    return ciphertext;
}

Result<SecretBytes> aead_decrypt(const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView ciphertext)
{
    if (!has_valid_sizes(key, nonce) || ciphertext.size() > aead_max_plaintext_size + aead_tag_size) {
        return std::unexpected(Error::invalid_size);
    }
    if (ciphertext.size() < aead_tag_size) {
        return std::unexpected(Error::authentication_failed);
    }
    require_operational();

    SecretBytes plaintext(ciphertext.size() - aead_tag_size);
    std::array<std::uint8_t, 1> empty_output{};
    std::uint8_t* output = plaintext.empty() ? empty_output.data() : plaintext.writable().data();
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            output, &written, nullptr, ciphertext.data(), ciphertext.size(), pointer_to(associated_data),
            associated_data.size(), nonce.data(), key.view().data())
        != 0) {
        return std::unexpected(Error::authentication_failed);
    }
    return plaintext;
}

}

Result<Bytes> aead_seal(const SecretBytes& key, ByteView associated_data, ByteView plaintext)
{
    const auto nonce = random_public_bytes<aead_nonce_size>();
    auto ciphertext = detail::aead_encrypt(key, nonce, associated_data, plaintext);
    if (!ciphertext) {
        return std::unexpected(ciphertext.error());
    }
    Bytes sealed(nonce.begin(), nonce.end());
    sealed.insert(sealed.end(), ciphertext->begin(), ciphertext->end());
    return sealed;
}

Result<SecretBytes> aead_open(const SecretBytes& key, ByteView associated_data, ByteView sealed)
{
    if (sealed.size() < aead_overhead) {
        return std::unexpected(Error::authentication_failed);
    }
    return detail::aead_decrypt(
        key, sealed.first(aead_nonce_size), associated_data, sealed.subspan(aead_nonce_size));
}

}
