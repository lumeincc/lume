// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/random.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>

namespace lume::crypto {
namespace {

TEST(Random, ArraysOfTheSameSizeDiffer)
{
    const auto first = random_public_bytes<32>();
    const auto second = random_public_bytes<32>();
    EXPECT_NE(first, second);
}

TEST(Random, SecretHasRequestedSizeAndIsNotAllZero)
{
    const auto secret = random_secret(64);
    ASSERT_EQ(secret.size(), 64U);
    EXPECT_FALSE(std::ranges::all_of(secret.view(), [](std::uint8_t byte) { return byte == 0; }));
}

TEST(Random, FillingAnEmptySpanIsANoOp)
{
    EXPECT_NO_THROW(random_fill(std::span<std::uint8_t>{}));
}

TEST(Random, ZeroSizedSecretIsEmpty)
{
    EXPECT_TRUE(random_secret(0).empty());
}

}
}
