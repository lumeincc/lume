// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/hex.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <optional>

namespace lume::test {
namespace {

TEST(Hex, DecodesUpperAndLowerCase)
{
    const auto bytes = decode_hex("00ff7Fa0");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (crypto::Bytes{0x00, 0xff, 0x7f, 0xa0}));
}

TEST(Hex, EmptyInputIsEmpty)
{
    EXPECT_EQ(decode_hex(""), std::optional<crypto::Bytes>(crypto::Bytes{}));
}

TEST(Hex, RejectsMalformedInput)
{
    EXPECT_FALSE(decode_hex("0").has_value());
    EXPECT_FALSE(decode_hex("0g").has_value());
    EXPECT_FALSE(decode_hex("zz").has_value());
    EXPECT_FALSE(decode_hex("00 1").has_value());
    EXPECT_FALSE(decode_hex("0011x0").has_value());
}

RC_GTEST_PROP(HexProperties, EncodeThenDecodeIsIdentity, (const crypto::Bytes& bytes))
{
    const auto decoded = decode_hex(encode_hex(bytes));
    RC_ASSERT(decoded.has_value());
    RC_ASSERT(*decoded == bytes);
}

}
}
