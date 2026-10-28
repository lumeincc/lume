// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace lume::seal {
namespace {

using crypto::Bytes;

Bytes filled(std::size_t size, std::uint8_t value)
{
    Bytes bytes(size, value);
    return bytes;
}

TEST(Padding, ChoosesTheSmallestBucketThatLeavesRoomForTheMarker)
{
    EXPECT_EQ(padded_size(0), 2048U);
    EXPECT_EQ(padded_size(2047), 2048U);
    EXPECT_EQ(padded_size(2048), 4096U);
    EXPECT_EQ(padded_size(65535), 65536U);
    EXPECT_EQ(padded_size(65536), 69632U);
    EXPECT_EQ(padded_size(largest_paddable_size), 69632U);
    EXPECT_EQ(padded_size(largest_paddable_size + 1), std::nullopt);
}

TEST(Padding, AppendsTheMarkerThenZeros)
{
    const auto padded = pad(filled(5, 0x41)).value();
    ASSERT_EQ(padded.size(), 2048U);
    EXPECT_EQ(Bytes(padded.begin(), padded.begin() + 5), filled(5, 0x41));
    EXPECT_EQ(padded.at(5), padding_marker);
    EXPECT_EQ(Bytes(padded.begin() + 6, padded.end()), filled(2042, 0));
}

TEST(Padding, KeepsTrailingZerosAndMarkersOfTheMessage)
{
    const Bytes message{0x00, 0x80, 0x00, 0x80, 0x00};
    EXPECT_EQ(unpad(pad(message).value()).value(), message);
}

TEST(Padding, RefusesAMessageTooLongForEveryBucket)
{
    EXPECT_EQ(pad(filled(largest_paddable_size + 1, 1)).error(), PaddingError::too_long);
    EXPECT_EQ(pad(filled(largest_paddable_size, 1)).value().size(), 69632U);
}

TEST(Padding, RefusesALengthThatIsNotABucket)
{
    auto padded = pad(filled(10, 1)).value();
    padded.push_back(0);
    EXPECT_EQ(unpad(padded).error(), PaddingError::malformed);
    padded.resize(2047);
    EXPECT_EQ(unpad(padded).error(), PaddingError::malformed);
    EXPECT_EQ(unpad(Bytes{}).error(), PaddingError::malformed);
}

TEST(Padding, RefusesAMissingOrWrongMarker)
{
    EXPECT_EQ(unpad(filled(2048, 0)).error(), PaddingError::malformed);
    auto padded = filled(2048, 0);
    padded.at(10) = 0x81;
    EXPECT_EQ(unpad(padded).error(), PaddingError::malformed);
    padded.at(10) = 0x80;
    padded.at(2047) = 0x01;
    EXPECT_EQ(unpad(padded).error(), PaddingError::malformed);
}

TEST(Padding, RefusesABucketLargerThanTheMessageNeeds)
{
    auto padded = filled(4096, 0);
    padded.at(10) = padding_marker;
    EXPECT_EQ(unpad(padded).error(), PaddingError::malformed);
}

TEST(Padding, AcceptsAMarkerAtTheLastByte)
{
    auto padded = filled(2048, 0x55);
    padded.at(2047) = padding_marker;
    EXPECT_EQ(unpad(padded).value(), filled(2047, 0x55));
}

RC_GTEST_PROP(PaddingProperties, RoundTripsAnyMessageThatFits, ())
{
    const auto size = *rc::gen::inRange<std::size_t>(0, largest_paddable_size + 1);
    const auto value = *rc::gen::arbitrary<std::uint8_t>();
    const auto message = filled(size, value);
    const auto padded = pad(message);
    RC_ASSERT(padded.has_value());
    RC_ASSERT(padded->size() == padded_size(size));
    RC_ASSERT(unpad(*padded).value() == message);
}

RC_GTEST_PROP(PaddingProperties, AcceptsOnlyTheCanonicalPaddingOfSomeMessage, (const Bytes& tail))
{
    const auto bucket = *rc::gen::elementOf(padding_buckets);
    auto input = filled(bucket, 0);
    const auto start = bucket - std::min(bucket, tail.size());
    std::ranges::copy(tail.begin(), tail.begin() + static_cast<std::ptrdiff_t>(bucket - start), input.begin() + static_cast<std::ptrdiff_t>(start));
    const auto message = unpad(input);
    if (message) {
        RC_ASSERT(pad(*message).value() == input);
    }
}

}
}
