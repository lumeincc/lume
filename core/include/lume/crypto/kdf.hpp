// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto {

inline constexpr std::size_t hmac_sha256_size = 32;
inline constexpr std::size_t hkdf_sha256_max_length = std::size_t{255} * hmac_sha256_size;

[[nodiscard]] SecretBytes hmac_sha256(ByteView key, ByteView message);

[[nodiscard]] Result<SecretBytes> hkdf_sha256(ByteView salt, ByteView input_key, ByteView info, std::size_t length);

}
