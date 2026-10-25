// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/aead.hpp"

#include "backend.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <expected>

namespace lume::crypto {

static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == aead_key_size);
static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == aead_nonce_size);
static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == aead_tag_size);

namespace {

bool has_valid_sizes(const SecretBytes& key, ByteView nonce)
{
    return key.size() == aead_key_size && nonce.size() == aead_nonce_size;
}

}

Result<Bytes> aead_seal(const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView plaintext)
{
    if (!has_valid_sizes(key, nonce) || plaintext.size() > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();

    Bytes ciphertext(plaintext.size() + aead_tag_size);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &written, plaintext.data(), plaintext.size(), associated_data.data(),
            associated_data.size(), nullptr, nonce.data(), key.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    ciphertext.resize(static_cast<std::size_t>(written));
    return ciphertext;
}

Result<SecretBytes> aead_open(const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView ciphertext)
{
    if (!has_valid_sizes(key, nonce)) {
        return std::unexpected(Error::invalid_size);
    }
    if (ciphertext.size() < aead_tag_size) {
        return std::unexpected(Error::authentication_failed);
    }
    detail::ensure_backends_ready();

    SecretBytes plaintext(ciphertext.size() - aead_tag_size);
    std::array<std::uint8_t, 1> empty_output{};
    std::uint8_t* output = plaintext.empty() ? empty_output.data() : plaintext.writable().data();
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            output, &written, nullptr, ciphertext.data(), ciphertext.size(), associated_data.data(),
            associated_data.size(), nonce.data(), key.view().data())
        != 0) {
        return std::unexpected(Error::authentication_failed);
    }
    return plaintext;
}

}
