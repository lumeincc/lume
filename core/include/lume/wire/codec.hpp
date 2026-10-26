// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/encoding.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace lume::wire {

enum class Error : std::uint8_t {
    truncated,
    over_bound,
    non_canonical,
    invalid_text,
    invalid_value,
    unsupported_version,
    trailing_bytes,
};

template <typename T>
using Result = std::expected<T, Error>;

[[nodiscard]] bool is_valid_text(crypto::ByteView text);

class Reader {
public:
    explicit Reader(crypto::ByteView input) noexcept;

    [[nodiscard]] Result<std::uint8_t> u8();
    [[nodiscard]] Result<std::uint16_t> u16();
    [[nodiscard]] Result<std::uint32_t> u32();
    [[nodiscard]] Result<std::uint64_t> u64();
    [[nodiscard]] Result<bool> boolean();
    [[nodiscard]] Result<bool> present();
    [[nodiscard]] Result<crypto::ByteView> fixed(std::size_t size);
    [[nodiscard]] Result<crypto::ByteView> bytes(std::size_t bound);
    [[nodiscard]] Result<std::string> text(std::size_t bound);
    [[nodiscard]] Result<std::size_t> count(std::size_t bound);
    [[nodiscard]] Result<void> finish() const;
    [[nodiscard]] std::size_t remaining() const noexcept;

    [[nodiscard]] bool into(std::uint8_t& target);
    [[nodiscard]] bool into(std::uint16_t& target);
    [[nodiscard]] bool into(std::uint32_t& target);
    [[nodiscard]] bool into(std::uint64_t& target);
    [[nodiscard]] bool into(bool& target);
    [[nodiscard]] bool into(crypto::Bytes& target, std::size_t bound);

    template <std::size_t Size>
    [[nodiscard]] bool into(crypto::ByteArray<Size>& target)
    {
        const auto view = fixed(Size);
        if (!view) {
            return fail(view.error());
        }
        std::ranges::copy(*view, target.begin());
        return true;
    }

    [[nodiscard]] bool fail(Error error) noexcept;
    [[nodiscard]] Error error() const noexcept;

    template <typename T>
    [[nodiscard]] Result<T> read_all(Result<T> (*read)(Reader&))
    {
        auto value = read(*this);
        if (!value) {
            return value;
        }
        if (const auto end = finish(); !end) {
            return std::unexpected(end.error());
        }
        return value;
    }

private:
    template <typename T>
    bool store(Result<T> value, T& target)
    {
        if (!value) {
            return fail(value.error());
        }
        target = *value;
        return true;
    }

    Result<std::uint64_t> big_endian(std::size_t size);

    crypto::ByteView rest_;
    Error error_ = Error::truncated;
};

class Writer {
public:
    Writer& u8(std::uint8_t value);
    Writer& u16(std::uint16_t value);
    Writer& u32(std::uint32_t value);
    Writer& u64(std::uint64_t value);
    Writer& boolean(bool value);
    Writer& present(bool value);
    Writer& fixed(crypto::ByteView value);
    Writer& bytes(crypto::ByteView value, std::size_t bound);
    Writer& text(std::string_view value, std::size_t bound);
    Writer& count(std::size_t value, std::size_t bound);

    [[nodiscard]] crypto::ByteView view() const noexcept;
    [[nodiscard]] crypto::Bytes take() noexcept;

private:
    crypto::Encoder encoder_;
};

}
