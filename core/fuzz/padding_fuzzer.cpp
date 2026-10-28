// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const auto input = std::span<const std::uint8_t>(data, size);
    const auto message = lume::seal::unpad(input);
    if (!message) {
        return 0;
    }
    const auto padded = lume::seal::pad(*message);
    if (!padded || !std::ranges::equal(*padded, input)) {
        std::abort();
    }
    return 0;
}
