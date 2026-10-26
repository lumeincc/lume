// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/codec.hpp"

#include <limits>
#include <stdexcept>

namespace lume::wire {
namespace {

constexpr std::uint8_t continuation_low = 0x80;
constexpr std::uint8_t continuation_high = 0xbf;
constexpr std::size_t bits_per_byte = 8;

struct Lead {
    std::size_t continuations = 0;
    std::uint8_t second_low = continuation_low;
    std::uint8_t second_high = continuation_high;
};

std::expected<Lead, Error> lead_of(std::uint8_t byte)
{
    if (byte == 0) {
        return std::unexpected(Error::invalid_text);
    }
    if (byte < continuation_low) {
        return Lead{.continuations = 0};
    }
    if (byte >= 0xc2 && byte <= 0xdf) {
        return Lead{.continuations = 1};
    }
    if (byte >= 0xe0 && byte <= 0xef) {
        return Lead{
            .continuations = 2,
            .second_low = byte == 0xe0 ? std::uint8_t{0xa0} : continuation_low,
            .second_high = byte == 0xed ? std::uint8_t{0x9f} : continuation_high};
    }
    if (byte >= 0xf0 && byte <= 0xf4) {
        return Lead{
            .continuations = 3,
            .second_low = byte == 0xf0 ? std::uint8_t{0x90} : continuation_low,
            .second_high = byte == 0xf4 ? std::uint8_t{0x8f} : continuation_high};
    }
    return std::unexpected(Error::invalid_text);
}

void require_within(std::size_t size, std::size_t bound)
{
    if (size > bound) {
        throw std::length_error("a wire value is larger than its bound");
    }
}

}

bool is_valid_text(crypto::ByteView text)
{
    std::size_t needed = 0;
    std::uint8_t low = continuation_low;
    std::uint8_t high = continuation_high;
    for (const std::uint8_t byte : text) {
        if (needed == 0) {
            const auto lead = lead_of(byte);
            if (!lead) {
                return false;
            }
            needed = lead->continuations;
            low = lead->second_low;
            high = lead->second_high;
            continue;
        }
        if (byte < low || byte > high) {
            return false;
        }
        low = continuation_low;
        high = continuation_high;
        --needed;
    }
    return needed == 0;
}

Reader::Reader(crypto::ByteView input) noexcept
    : rest_(input)
{
}

Result<std::uint64_t> Reader::big_endian(std::size_t size)
{
    if (rest_.size() < size) {
        return std::unexpected(Error::truncated);
    }
    std::uint64_t value = 0;
    for (const std::uint8_t byte : rest_.first(size)) {
        value = (value << bits_per_byte) | byte;
    }
    rest_ = rest_.subspan(size);
    return value;
}

Result<std::uint8_t> Reader::u8()
{
    return big_endian(sizeof(std::uint8_t)).transform([](std::uint64_t value) {
        return static_cast<std::uint8_t>(value);
    });
}

Result<std::uint16_t> Reader::u16()
{
    return big_endian(sizeof(std::uint16_t)).transform([](std::uint64_t value) {
        return static_cast<std::uint16_t>(value);
    });
}

Result<std::uint32_t> Reader::u32()
{
    return big_endian(sizeof(std::uint32_t)).transform([](std::uint64_t value) {
        return static_cast<std::uint32_t>(value);
    });
}

Result<std::uint64_t> Reader::u64()
{
    return big_endian(sizeof(std::uint64_t));
}

Result<bool> Reader::boolean()
{
    const auto value = u8();
    if (!value) {
        return std::unexpected(value.error());
    }
    if (*value > 1) {
        return std::unexpected(Error::non_canonical);
    }
    return *value == 1;
}

Result<bool> Reader::present()
{
    return boolean();
}

Result<crypto::ByteView> Reader::fixed(std::size_t size)
{
    if (rest_.size() < size) {
        return std::unexpected(Error::truncated);
    }
    const auto value = rest_.first(size);
    rest_ = rest_.subspan(size);
    return value;
}

Result<crypto::ByteView> Reader::bytes(std::size_t bound)
{
    const auto length = u32();
    if (!length) {
        return std::unexpected(length.error());
    }
    if (*length > bound) {
        return std::unexpected(Error::over_bound);
    }
    return fixed(*length);
}

Result<std::string> Reader::text(std::size_t bound)
{
    const auto value = bytes(bound);
    if (!value) {
        return std::unexpected(value.error());
    }
    if (!is_valid_text(*value)) {
        return std::unexpected(Error::invalid_text);
    }
    std::string text;
    text.reserve(value->size());
    for (const std::uint8_t byte : *value) {
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

Result<std::size_t> Reader::count(std::size_t bound)
{
    const auto value = u16();
    if (!value) {
        return std::unexpected(value.error());
    }
    if (*value > bound) {
        return std::unexpected(Error::over_bound);
    }
    return std::size_t{*value};
}

Result<void> Reader::finish() const
{
    if (!rest_.empty()) {
        return std::unexpected(Error::trailing_bytes);
    }
    return {};
}

std::size_t Reader::remaining() const noexcept
{
    return rest_.size();
}

bool Reader::into(std::uint8_t& target)
{
    return store(u8(), target);
}

bool Reader::into(std::uint16_t& target)
{
    return store(u16(), target);
}

bool Reader::into(std::uint32_t& target)
{
    return store(u32(), target);
}

bool Reader::into(std::uint64_t& target)
{
    return store(u64(), target);
}

bool Reader::into(bool& target)
{
    return store(boolean(), target);
}

bool Reader::into(crypto::Bytes& target, std::size_t bound)
{
    const auto view = bytes(bound);
    if (!view) {
        return fail(view.error());
    }
    target.assign(view->begin(), view->end());
    return true;
}

bool Reader::fail(Error error) noexcept
{
    error_ = error;
    return false;
}

Error Reader::error() const noexcept
{
    return error_;
}

Writer& Writer::u8(std::uint8_t value)
{
    encoder_.u8(value);
    return *this;
}

Writer& Writer::u16(std::uint16_t value)
{
    encoder_.u16(value);
    return *this;
}

Writer& Writer::u32(std::uint32_t value)
{
    encoder_.u32(value);
    return *this;
}

Writer& Writer::u64(std::uint64_t value)
{
    encoder_.u64(value);
    return *this;
}

Writer& Writer::boolean(bool value)
{
    encoder_.u8(static_cast<std::uint8_t>(value ? 1U : 0U));
    return *this;
}

Writer& Writer::present(bool value)
{
    return boolean(value);
}

Writer& Writer::fixed(crypto::ByteView value)
{
    encoder_.raw(value);
    return *this;
}

Writer& Writer::bytes(crypto::ByteView value, std::size_t bound)
{
    require_within(value.size(), bound);
    encoder_.prefixed(value);
    return *this;
}

Writer& Writer::text(std::string_view value, std::size_t bound)
{
    crypto::Bytes bytes;
    bytes.reserve(value.size());
    for (const char character : value) {
        bytes.push_back(static_cast<std::uint8_t>(character));
    }
    if (!is_valid_text(bytes)) {
        throw std::invalid_argument("wire text must be valid UTF-8 without NUL");
    }
    return this->bytes(bytes, bound);
}

Writer& Writer::count(std::size_t value, std::size_t bound)
{
    require_within(value, std::min<std::size_t>(bound, std::numeric_limits<std::uint16_t>::max()));
    encoder_.u16(static_cast<std::uint16_t>(value));
    return *this;
}

crypto::ByteView Writer::view() const noexcept
{
    return encoder_.view();
}

crypto::Bytes Writer::take() noexcept
{
    return encoder_.take();
}

}
