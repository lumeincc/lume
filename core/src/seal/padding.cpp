// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <optional>
#include <ranges>

namespace lume::seal {

std::optional<std::size_t> padded_size(std::size_t message_size) noexcept
{
    for (const auto size : padding_buckets) {
        if (message_size < size) {
            return size;
        }
    }
    return std::nullopt;
}

PaddingResult<crypto::Bytes> pad(crypto::ByteView message)
{
    const auto size = padded_size(message.size());
    if (!size) {
        return std::unexpected(PaddingError::too_long);
    }
    crypto::Bytes padded(*size, 0);
    std::ranges::copy(message, padded.begin());
    padded.at(message.size()) = padding_marker;
    return padded;
}

PaddingResult<crypto::Bytes> unpad(crypto::ByteView padded)
{
    if (std::ranges::find(padding_buckets, padded.size()) == padding_buckets.end()) {
        return std::unexpected(PaddingError::malformed);
    }
    const auto reversed = padded | std::views::reverse;
    const auto marker = std::ranges::find_if(reversed, [](std::uint8_t byte) { return byte != 0; });
    if (marker == reversed.end() || *marker != padding_marker) {
        return std::unexpected(PaddingError::malformed);
    }
    const auto message_size = static_cast<std::size_t>(std::ranges::distance(std::next(marker), reversed.end()));
    if (padded_size(message_size) != padded.size()) {
        return std::unexpected(PaddingError::malformed);
    }
    const auto message = padded.first(message_size);
    return crypto::Bytes(message.begin(), message.end());
}

}
