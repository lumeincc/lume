// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/encoding.hpp"

#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <string>

namespace lume::crypto {
namespace {

TEST(Encoder, WritesBigEndianIntegers)
{
    Encoder encoder;
    encoder.u8(0x01).u16(0x0203).u32(0x04050607).u64(0x08090a0b0c0d0e0f);
    EXPECT_EQ(test::to_hex(encoder.view()), "0102030405060708090a0b0c0d0e0f");
}

TEST(Encoder, PrefixesTheLength)
{
    EXPECT_EQ(test::to_hex(Encoder{}.prefixed(Bytes{0xaa, 0xbb}).view()), "00000002aabb");
    EXPECT_EQ(test::to_hex(Encoder{}.prefixed({}).view()), "00000000");
}

TEST(Encoder, RawBytesAreCopiedAsTheyAre)
{
    EXPECT_EQ(test::to_hex(Encoder{}.raw(Bytes{0x00, 0xff}).raw({}).view()), "00ff");
}

TEST(Encoder, LabelIsTheLengthPrefixedVersionedName)
{
    EXPECT_EQ(test::to_hex(label("device")), "0000000e" + test::to_hex(Bytes{'L', 'U', 'M', 'E', '/', 'v', '1', '/', 'd', 'e', 'v', 'i', 'c', 'e'}));
    EXPECT_EQ(test::to_hex(label("")), "000000084c554d452f76312f");
}

TEST(Encoder, TakeEmptiesTheEncoder)
{
    Encoder encoder;
    encoder.u8(7);
    EXPECT_EQ(encoder.take(), Bytes{7});
    EXPECT_TRUE(encoder.view().empty());
}

RC_GTEST_PROP(EncodingProperties, PrefixedPairsAreUnambiguous,
    (const Bytes& first, const Bytes& second, const Bytes& third, const Bytes& fourth))
{
    RC_PRE(first != third || second != fourth);
    const auto left = Encoder{}.prefixed(first).prefixed(second).take();
    const auto right = Encoder{}.prefixed(third).prefixed(fourth).take();
    RC_ASSERT(left != right);
}

RC_GTEST_PROP(EncodingProperties, NoLabelIsAPrefixOfAnother, (const std::string& first, const std::string& second))
{
    RC_PRE(first != second);
    const auto left = label(first);
    const auto right = label(second);
    const auto shorter = std::min(left.size(), right.size());
    RC_ASSERT_FALSE(std::ranges::equal(ByteView(left).first(shorter), ByteView(right).first(shorter)));
}

}
}
