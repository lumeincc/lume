// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t aead_key_size = 32;
inline constexpr std::size_t aead_nonce_size = 24;
inline constexpr std::size_t aead_tag_size = 16;
inline constexpr std::size_t aead_overhead = aead_nonce_size + aead_tag_size;
inline constexpr std::size_t aead_max_plaintext_size = std::size_t{128} * 1024;

[[nodiscard]] Result<Bytes> aead_seal(const SecretBytes& key, ByteView associated_data, ByteView plaintext);

[[nodiscard]] Result<SecretBytes> aead_open(const SecretBytes& key, ByteView associated_data, ByteView sealed);

}
