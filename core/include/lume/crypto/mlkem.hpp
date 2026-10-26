// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t mlkem768_public_key_size = 1184;
inline constexpr std::size_t mlkem768_ciphertext_size = 1088;
inline constexpr std::size_t mlkem768_shared_secret_size = 32;
inline constexpr std::size_t mlkem768_seed_size = 64;

struct MlKemKeyPair {
    Bytes public_key;
    SecretBytes seed;
};

struct MlKemEncapsulation {
    Bytes ciphertext;
    SecretBytes shared_secret;
};

[[nodiscard]] MlKemKeyPair mlkem768_generate();

[[nodiscard]] Result<MlKemKeyPair> mlkem768_from_seed(SecretBytes seed);

[[nodiscard]] Result<MlKemEncapsulation> mlkem768_encapsulate(ByteView public_key);

[[nodiscard]] Result<SecretBytes> mlkem768_decapsulate(const SecretBytes& seed, ByteView ciphertext);

}
