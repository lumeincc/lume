// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t x25519_key_size = 32;

struct X25519KeyPair {
    ByteArray<x25519_key_size> public_key;
    SecretBytes secret_key;
};

[[nodiscard]] X25519KeyPair x25519_generate();

[[nodiscard]] Result<X25519KeyPair> x25519_from_secret(SecretBytes secret_key);

[[nodiscard]] Result<SecretBytes> x25519_shared_secret(const SecretBytes& secret_key, ByteView peer_public_key);

}
