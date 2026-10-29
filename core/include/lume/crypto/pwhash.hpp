// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace lume::crypto {

inline constexpr std::size_t argon2id_salt_size = 16;
inline constexpr std::size_t argon2id_key_size = 32;

[[nodiscard]] Result<SecretBytes> argon2id(
    std::string_view passphrase, ByteView salt, std::uint32_t passes, std::uint32_t memory_kib);

}
