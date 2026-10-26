// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/x25519.hpp"

#include "backend.hpp"
#include "lume/crypto/random.hpp"

#include <sodium.h>

#include <algorithm>
#include <expected>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace lume::crypto {

static_assert(crypto_scalarmult_BYTES == x25519_key_size);
static_assert(crypto_scalarmult_SCALARBYTES == x25519_key_size);

bool x25519_is_canonical(ByteView public_key)
{
    static constexpr ByteArray<x25519_key_size> field_prime{
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    if (public_key.size() != x25519_key_size) {
        return false;
    }
    return std::ranges::lexicographical_compare(public_key | std::views::reverse, field_prime | std::views::reverse);
}

X25519KeyPair x25519_generate()
{
    auto key_pair = x25519_from_secret(random_secret(x25519_key_size));
    if (!key_pair) {
        throw std::runtime_error("X25519 key generation failed");
    }
    return std::move(*key_pair);
}

Result<X25519KeyPair> x25519_from_secret(SecretBytes secret_key)
{
    if (secret_key.size() != x25519_key_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::require_operational();
    ByteArray<x25519_key_size> public_key{};
    if (crypto_scalarmult_base(public_key.data(), secret_key.view().data()) != 0) {
        return std::unexpected(Error::invalid_key);
    }
    return X25519KeyPair{.public_key = public_key, .secret_key = std::move(secret_key)};
}

Result<SecretBytes> x25519_shared_secret(const SecretBytes& secret_key, ByteView peer_public_key)
{
    if (secret_key.size() != x25519_key_size || peer_public_key.size() != x25519_key_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::require_operational();
    SecretBytes shared(x25519_key_size);
    if (crypto_scalarmult(shared.writable().data(), secret_key.view().data(), peer_public_key.data()) != 0) {
        return std::unexpected(Error::weak_public_key);
    }
    return shared;
}

}
