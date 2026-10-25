// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "crypto/hex.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

namespace lume::crypto::detail {
namespace {

TEST(Hex, DecodesUpperAndLowerCase)
{
    const auto bytes = decode_hex("00ff7Fa0");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (Bytes{0x00, 0xff, 0x7f, 0xa0}));
}

TEST(Hex, EmptyInputIsEmpty)
{
    const auto bytes = decode_hex("");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_TRUE(bytes->empty());
}

TEST(Hex, RejectsMalformedInput)
{
    EXPECT_FALSE(decode_hex("0").has_value());
    EXPECT_FALSE(decode_hex("0g").has_value());
    EXPECT_FALSE(decode_hex("zz").has_value());
    EXPECT_FALSE(decode_hex("00 1").has_value());
    EXPECT_FALSE(decode_hex("0011x0").has_value());
}

RC_GTEST_PROP(HexProperties, EncodeThenDecodeIsIdentity, (const Bytes& bytes))
{
    const auto decoded = decode_hex(encode_hex(bytes));
    RC_ASSERT(decoded.has_value());
    RC_ASSERT(*decoded == bytes);
}

}
}
