// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include "support/properties.hpp"

#include <cstddef>
#include <cstdint>

namespace lume::test {

inline crypto::Bytes flip_bit(crypto::ByteView bytes, std::size_t index, unsigned bit)
{
    crypto::Bytes copy(bytes.begin(), bytes.end());
    copy.at(index) = static_cast<std::uint8_t>(copy.at(index) ^ (1U << bit));
    return copy;
}

inline crypto::Bytes flip_random_bit(crypto::ByteView bytes)
{
    const auto index = *rc::gen::inRange<std::size_t>(0, bytes.size());
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    return flip_bit(bytes, index, bit);
}

inline crypto::Bytes random_bytes_of(std::size_t size)
{
    return *rc::gen::container<crypto::Bytes>(
        size, rc::gen::map(rc::gen::inRange(0, 256), [](int value) { return static_cast<std::uint8_t>(value); }));
}

}
