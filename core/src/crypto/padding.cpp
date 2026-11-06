// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "crypto/padding.hpp"

#include <algorithm>
#include <iterator>
#include <ranges>

namespace lume::crypto::detail {

std::optional<std::size_t> padded_size(std::size_t message_size, std::span<const std::size_t> buckets) noexcept
{
    for (const auto size : buckets) {
        if (message_size < size) {
            return size;
        }
    }
    return std::nullopt;
}

bool pad_into(ByteView message, std::span<std::uint8_t> padded, std::span<const std::size_t> buckets) noexcept
{
    if (padded_size(message.size(), buckets) != padded.size()) {
        return false;
    }
    const auto marker = std::ranges::copy(message, padded.begin()).out;
    *marker = padding_marker;
    std::ranges::fill(std::next(marker), padded.end(), std::uint8_t{0});
    return true;
}

std::optional<ByteView> unpad(ByteView padded, std::span<const std::size_t> buckets) noexcept
{
    const auto reversed = padded | std::views::reverse;
    const auto marker = std::ranges::find_if(reversed, [](std::uint8_t byte) { return byte != 0; });
    if (marker == reversed.end() || *marker != padding_marker) {
        return std::nullopt;
    }
    const auto message_size = static_cast<std::size_t>(std::ranges::distance(std::next(marker), reversed.end()));
    if (padded_size(message_size, buckets) != padded.size()) {
        return std::nullopt;
    }
    return padded.first(message_size);
}

}
