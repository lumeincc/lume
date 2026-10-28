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
    if (input.size() <= lume::seal::largest_paddable_size) {
        const auto padded = lume::seal::pad(input);
        if (!padded) {
            std::abort();
        }
        const auto unpadded = lume::seal::unpad(*padded);
        if (!unpadded || !std::ranges::equal(*unpadded, input)) {
            std::abort();
        }
    }
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
