// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"
#include "lume/wire/structures.hpp"
#include "seal/seal_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> input(data, size);
    const auto inner = lume::seal::detail::inner_of(input);
    if (!inner) {
        return 0;
    }
    if (inner->initial && inner->initial->ik_sig != inner->sender) {
        std::abort();
    }
    const auto padded = lume::seal::pad(lume::wire::encode(*inner));
    if (!padded || !std::ranges::equal(*padded, input)) {
        std::abort();
    }
    return 0;
}
