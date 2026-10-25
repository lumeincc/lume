// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/ed25519.hpp"

#include "backend.hpp"
#include "lume/crypto/random.hpp"

#include <sodium.h>

#include <expected>
#include <stdexcept>
#include <utility>

namespace lume::crypto {

static_assert(crypto_sign_PUBLICKEYBYTES == ed25519_public_key_size);
static_assert(crypto_sign_SECRETKEYBYTES == ed25519_secret_key_size);
static_assert(crypto_sign_SEEDBYTES == ed25519_seed_size);
static_assert(crypto_sign_BYTES == ed25519_signature_size);

Ed25519KeyPair ed25519_generate()
{
    auto key_pair = ed25519_from_seed(random_secret(ed25519_seed_size));
    if (!key_pair) {
        throw std::runtime_error("Ed25519 key generation failed");
    }
    return std::move(*key_pair);
}

Result<Ed25519KeyPair> ed25519_from_seed(const SecretBytes& seed)
{
    if (seed.size() != ed25519_seed_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    Ed25519KeyPair key_pair{.public_key = {}, .secret_key = SecretBytes(ed25519_secret_key_size)};
    if (crypto_sign_seed_keypair(key_pair.public_key.data(), key_pair.secret_key.writable().data(), seed.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    return key_pair;
}

Result<ByteArray<ed25519_signature_size>> ed25519_sign(const SecretBytes& secret_key, ByteView message)
{
    if (secret_key.size() != ed25519_secret_key_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    ByteArray<ed25519_signature_size> signature{};
    if (crypto_sign_detached(
            signature.data(), nullptr, detail::pointer_to(message), message.size(), secret_key.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    return signature;
}

bool ed25519_verify(ByteView public_key, ByteView message, ByteView signature)
{
    if (public_key.size() != ed25519_public_key_size || signature.size() != ed25519_signature_size) {
        return false;
    }
    detail::ensure_backends_ready();
    return crypto_sign_verify_detached(
               signature.data(), detail::pointer_to(message), message.size(), public_key.data())
        == 0;
}

}
