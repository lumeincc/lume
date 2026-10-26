// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>

namespace lume::identity {

inline constexpr std::size_t entropy_size = 32;
inline constexpr std::size_t phrase_word_count = 24;

enum class PhraseError : std::uint8_t {
    invalid_character,
    wrong_word_count,
    unknown_word,
    checksum_mismatch,
};

[[nodiscard]] crypto::Result<crypto::SecretBytes> phrase_from_entropy(const crypto::SecretBytes& entropy);

[[nodiscard]] std::expected<crypto::SecretBytes, PhraseError> entropy_from_phrase(crypto::ByteView phrase);

}
