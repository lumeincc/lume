// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t ed25519_public_key_size = 32;
inline constexpr std::size_t ed25519_seed_size = 32;
inline constexpr std::size_t ed25519_signature_size = 64;

struct Ed25519KeyPair {
    ByteArray<ed25519_public_key_size> public_key;
    SecretBytes seed;
};

[[nodiscard]] Ed25519KeyPair ed25519_generate();

[[nodiscard]] Result<Ed25519KeyPair> ed25519_from_seed(SecretBytes seed);

[[nodiscard]] Result<ByteArray<ed25519_signature_size>> ed25519_sign(const SecretBytes& seed, ByteView message);

[[nodiscard]] bool ed25519_verify(ByteView public_key, ByteView message, ByteView signature);

}
