// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstdint>
#include <span>

namespace lume::crypto::detail {

[[nodiscard]] Result<Bytes> aead_encrypt(
    const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView plaintext);

[[nodiscard]] Result<SecretBytes> aead_decrypt(
    const SecretBytes& key, ByteView nonce, ByteView associated_data, ByteView ciphertext);

[[nodiscard]] Result<SecretBytes> aead_open(ByteView key, ByteView associated_data, ByteView sealed);

[[nodiscard]] Result<void> aead_open_into(
    ByteView key, ByteView associated_data, ByteView sealed, std::span<std::uint8_t> plaintext);

}
