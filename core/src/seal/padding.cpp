// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include "lume/crypto/aead.hpp"
#include "lume/wire/structures.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <optional>
#include <ranges>

namespace lume::seal {

static_assert(padding_buckets.back() + crypto::aead_tag_size == wire::seal_box_bound);

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
    crypto::Bytes padded;
    padded.reserve(*size);
    padded.assign(message.begin(), message.end());
    padded.push_back(padding_marker);
    padded.resize(*size, 0);
    return padded;
}

PaddingResult<crypto::ByteView> unpad(crypto::ByteView padded) noexcept
{
    if (!std::ranges::contains(padding_buckets, padded.size())) {
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
    return padded.first(message_size);
}

}
