// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "crypto/padding.hpp"
#include "lume/seal/padding.hpp"
#include "vault/records.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace {

void expect_bucket_round_trip(std::span<const std::uint8_t> input, std::span<const std::size_t> buckets)
{
    const auto message = lume::crypto::detail::unpad(input, buckets);
    if (!message) {
        return;
    }
    lume::crypto::Bytes padded(input.size());
    if (!lume::crypto::detail::pad_into(*message, padded, buckets) || !std::ranges::equal(padded, input)) {
        std::abort();
    }
}

}

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
    expect_bucket_round_trip(input, lume::vault::record_buckets);
    expect_bucket_round_trip(input, lume::vault::manifest_buckets);
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
