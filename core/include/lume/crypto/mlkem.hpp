// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t mlkem768_public_key_size = 1184;
inline constexpr std::size_t mlkem768_secret_key_size = 2400;
inline constexpr std::size_t mlkem768_ciphertext_size = 1088;
inline constexpr std::size_t mlkem768_shared_secret_size = 32;
inline constexpr std::size_t mlkem768_key_seed_size = 64;
inline constexpr std::size_t mlkem768_encapsulation_seed_size = 32;

struct MlKemKeyPair {
    Bytes public_key;
    SecretBytes secret_key;
};

struct MlKemEncapsulation {
    Bytes ciphertext;
    SecretBytes shared_secret;
};

[[nodiscard]] Result<MlKemKeyPair> mlkem768_generate();

[[nodiscard]] Result<MlKemKeyPair> mlkem768_from_seed(const SecretBytes& seed);

[[nodiscard]] Result<MlKemEncapsulation> mlkem768_encapsulate(ByteView public_key);

[[nodiscard]] Result<MlKemEncapsulation> mlkem768_encapsulate_deterministic(
    ByteView public_key, const SecretBytes& seed);

[[nodiscard]] Result<SecretBytes> mlkem768_decapsulate(const SecretBytes& secret_key, ByteView ciphertext);

}
