// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include "crypto/padding.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <expected>
#include <optional>

namespace lume::seal {

static_assert(padding_buckets.back() + crypto::aead_tag_size == wire::seal_box_bound);
static_assert(padding_marker == crypto::detail::padding_marker);

std::optional<std::size_t> padded_size(std::size_t message_size) noexcept
{
    return crypto::detail::padded_size(message_size, padding_buckets);
}

PaddingResult<crypto::Bytes> pad(crypto::ByteView message)
{
    const auto size = padded_size(message.size());
    if (!size) {
        return std::unexpected(PaddingError::too_long);
    }
    crypto::Bytes padded(*size);
    if (!crypto::detail::pad_into(message, padded, padding_buckets)) {
        return std::unexpected(PaddingError::too_long);
    }
    return padded;
}

PaddingResult<crypto::ByteView> unpad(crypto::ByteView padded) noexcept
{
    const auto message = crypto::detail::unpad(padded, padding_buckets);
    if (!message) {
        return std::unexpected(PaddingError::malformed);
    }
    return *message;
}

}
