// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace lume::crypto::detail {

inline constexpr std::uint8_t padding_marker = 0x80;

[[nodiscard]] std::optional<std::size_t> padded_size(std::size_t message_size, std::span<const std::size_t> buckets) noexcept;

[[nodiscard]] bool pad_into(ByteView message, std::span<std::uint8_t> padded, std::span<const std::size_t> buckets) noexcept;

[[nodiscard]] std::optional<ByteView> unpad(ByteView padded, std::span<const std::size_t> buckets) noexcept;

}
