// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/encoding.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace lume::crypto {

Encoder& Encoder::u8(std::uint8_t value)
{
    bytes_.push_back(value);
    return *this;
}

Encoder& Encoder::u16(std::uint16_t value)
{
    append_big_endian(value, sizeof value);
    return *this;
}

Encoder& Encoder::u32(std::uint32_t value)
{
    append_big_endian(value, sizeof value);
    return *this;
}

Encoder& Encoder::u64(std::uint64_t value)
{
    append_big_endian(value, sizeof value);
    return *this;
}

Encoder& Encoder::raw(ByteView bytes)
{
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
    return *this;
}

Encoder& Encoder::prefixed(ByteView bytes)
{
    append_length(bytes.size());
    return raw(bytes);
}

Encoder& Encoder::label(std::string_view name)
{
    append_length(label_prefix.size() + name.size());
    for (const std::string_view part : {label_prefix, name}) {
        for (const char character : part) {
            bytes_.push_back(static_cast<std::uint8_t>(character));
        }
    }
    return *this;
}

ByteView Encoder::view() const noexcept
{
    return bytes_;
}

Bytes Encoder::take() noexcept
{
    return std::exchange(bytes_, {});
}

void Encoder::append_big_endian(std::uint64_t value, std::size_t size)
{
    for (std::size_t remaining = size; remaining > 0; --remaining) {
        bytes_.push_back(static_cast<std::uint8_t>(value >> ((remaining - 1) * 8)));
    }
}

void Encoder::append_length(std::size_t length)
{
    if (length > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("a length-prefixed value is limited to 2^32 - 1 bytes");
    }
    u32(static_cast<std::uint32_t>(length));
}

Bytes label(std::string_view name)
{
    return Encoder{}.label(name).take();
}

}
