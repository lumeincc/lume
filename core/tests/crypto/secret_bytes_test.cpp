// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/secret_bytes.hpp"

#include "support/mutate.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace lume::crypto {
namespace {

TEST(SecretBytes, DefaultConstructedIsEmpty)
{
    const SecretBytes secret;
    EXPECT_TRUE(secret.empty());
    EXPECT_EQ(secret.size(), 0U);
    EXPECT_TRUE(secret.view().empty());
}

TEST(SecretBytes, NewAllocationIsZeroed)
{
    const SecretBytes secret(64);
    ASSERT_EQ(secret.size(), 64U);
    EXPECT_TRUE(std::ranges::all_of(secret.view(), [](std::uint8_t byte) { return byte == 0; }));
}

TEST(SecretBytes, ZeroSizeAllocationIsEmpty)
{
    const SecretBytes secret(0);
    EXPECT_TRUE(secret.empty());
    EXPECT_TRUE(secret.equals({}));
}

TEST(SecretBytes, EqualsRejectsDifferentLength)
{
    const Bytes bytes{1, 2, 3, 4};
    const auto secret = SecretBytes::copy_of(bytes);
    EXPECT_FALSE(secret.equals(ByteView(bytes).first(3)));
    EXPECT_FALSE(SecretBytes(0).equals(bytes));
}

TEST(SecretBytes, MoveConstructionTransfersOwnership)
{
    const Bytes bytes{9, 8, 7};
    auto source = SecretBytes::copy_of(bytes);
    const SecretBytes* const moved_from = &source;
    const SecretBytes target(std::move(source));
    EXPECT_TRUE(target.equals(bytes));
    EXPECT_TRUE(moved_from->empty());
}

TEST(SecretBytes, MoveAssignmentReplacesContent)
{
    const Bytes first{1, 1, 1};
    const Bytes second{2, 2, 2, 2};
    auto target = SecretBytes::copy_of(first);
    auto source = SecretBytes::copy_of(second);
    const SecretBytes* const moved_from = &source;
    target = std::move(source);
    EXPECT_TRUE(target.equals(second));
    EXPECT_TRUE(moved_from->empty());
}

TEST(SecretBytes, CloneIsIndependent)
{
    const Bytes bytes{5, 6, 7};
    const auto original = SecretBytes::copy_of(bytes);
    auto copy = original.clone();
    copy.writable().front() = 0;
    EXPECT_TRUE(original.equals(bytes));
    EXPECT_FALSE(copy.equals(bytes));
}

RC_GTEST_PROP(SecretBytesProperties, CopyOfPreservesEveryByte, (const Bytes& bytes))
{
    const auto secret = SecretBytes::copy_of(bytes);
    RC_ASSERT(secret.size() == bytes.size());
    RC_ASSERT(std::ranges::equal(secret.view(), bytes));
    RC_ASSERT(secret.equals(bytes));
}

RC_GTEST_PROP(SecretBytesProperties, EqualsDetectsAnySingleBitChange, (const Bytes& bytes))
{
    RC_PRE(!bytes.empty());
    const auto secret = SecretBytes::copy_of(bytes);
    RC_ASSERT_FALSE(secret.equals(test::flip_random_bit(bytes)));
}

}
}
