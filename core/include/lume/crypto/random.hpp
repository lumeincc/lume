// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace lume::crypto {

void random_fill(std::span<std::uint8_t> output);

[[nodiscard]] SecretBytes random_secret(std::size_t size);

template <std::size_t Size>
[[nodiscard]] ByteArray<Size> random_public_bytes()
{
    ByteArray<Size> output{};
    random_fill(output);
    return output;
}

}
