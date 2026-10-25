// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <initializer_list>

namespace lume::crypto {

inline constexpr std::size_t sha256_size = 32;
inline constexpr std::size_t sha512_size = 64;

[[nodiscard]] ByteArray<sha256_size> sha256(ByteView data);
[[nodiscard]] ByteArray<sha256_size> sha256(std::initializer_list<ByteView> parts);
[[nodiscard]] ByteArray<sha512_size> sha512(ByteView data);
[[nodiscard]] ByteArray<sha512_size> sha512(std::initializer_list<ByteView> parts);

}
