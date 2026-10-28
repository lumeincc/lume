// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

namespace lume::seal {

inline constexpr std::array<std::size_t, 7> padding_buckets{2048, 4096, 8192, 16384, 32768, 65536, 69632};
inline constexpr std::size_t largest_paddable_size = padding_buckets.back() - 1;
inline constexpr std::uint8_t padding_marker = 0x80;

enum class PaddingError : std::uint8_t {
    too_long,
    malformed,
};

template <typename T>
using PaddingResult = std::expected<T, PaddingError>;

[[nodiscard]] std::optional<std::size_t> padded_size(std::size_t message_size) noexcept;

[[nodiscard]] PaddingResult<crypto::Bytes> pad(crypto::ByteView message);

[[nodiscard]] PaddingResult<crypto::ByteView> unpad(crypto::ByteView padded) noexcept;

}
