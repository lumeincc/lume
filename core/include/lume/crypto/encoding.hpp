// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace lume::crypto {

inline constexpr std::string_view label_prefix = "LUME/v1/";

class Encoder {
public:
    Encoder& u8(std::uint8_t value);
    Encoder& u16(std::uint16_t value);
    Encoder& u32(std::uint32_t value);
    Encoder& u64(std::uint64_t value);
    Encoder& raw(ByteView bytes);
    Encoder& prefixed(ByteView bytes);
    Encoder& label(std::string_view name);

    [[nodiscard]] ByteView view() const noexcept;
    [[nodiscard]] Bytes take() noexcept;

private:
    void append_big_endian(std::uint64_t value, std::size_t size);
    void append_length(std::size_t length);

    Bytes bytes_;
};

[[nodiscard]] Bytes label(std::string_view name);

}
