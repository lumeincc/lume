// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/padding.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace lume::seal {
namespace {

using crypto::Bytes;
using crypto::ByteView;

Bytes patterned(std::size_t size, std::uint32_t seed)
{
    Bytes bytes(size);
    auto state = seed | 1U;
    for (auto& byte : bytes) {
        state ^= state << 13U;
        state ^= state >> 17U;
        state ^= state << 5U;
        byte = static_cast<std::uint8_t>(state);
    }
    return bytes;
}

Bytes padded_by_hand(ByteView message, std::size_t bucket)
{
    Bytes bytes(message.begin(), message.end());
    bytes.push_back(padding_marker);
    bytes.resize(bucket, 0);
    return bytes;
}

Bytes copied(ByteView view)
{
    return {view.begin(), view.end()};
}

bool refused(const PaddingResult<ByteView>& result)
{
    return !result.has_value() && result.error() == PaddingError::malformed;
}

bool reference_accepts(ByteView input)
{
    if (!std::ranges::contains(padding_buckets, input.size())) {
        return false;
    }
    for (std::size_t index = input.size(); index > 0; --index) {
        const auto byte = input.subspan(index - 1).front();
        if (byte != 0) {
            return byte == padding_marker && padded_size(index - 1) == input.size();
        }
    }
    return false;
}

std::vector<std::size_t> edge_sizes()
{
    std::vector<std::size_t> sizes{0, largest_paddable_size};
    for (const auto bucket : padding_buckets) {
        for (const auto size : {bucket - 1, bucket, bucket + 1}) {
            if (size <= largest_paddable_size) {
                sizes.push_back(size);
            }
        }
    }
    return sizes;
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
    const auto message = patterned(5, 7);
    const auto padded = pad(message);
    ASSERT_TRUE(padded.has_value());
    EXPECT_EQ(*padded, padded_by_hand(message, 2048));
}

TEST(Padding, AcceptsWhatPadProducesAtEveryBucketEdge)
{
    for (const auto size : edge_sizes()) {
        const auto message = patterned(size, static_cast<std::uint32_t>(size));
        const auto padded = pad(message);
        ASSERT_TRUE(padded.has_value()) << size;
        EXPECT_EQ(padded->size(), padded_size(size)) << size;
        EXPECT_EQ(padded->at(size), padding_marker) << size;
        const auto unpadded = unpad(*padded);
        ASSERT_TRUE(unpadded.has_value()) << size;
        EXPECT_EQ(copied(*unpadded), message) << size;
    }
}

TEST(Padding, RefusesAMarkerThatWouldFitTheBucketBelow)
{
    for (std::size_t index = 1; index < padding_buckets.size(); ++index) {
        const auto bucket = padding_buckets.at(index);
        const auto below = padding_buckets.at(index - 1);
        const auto fits_below = padded_by_hand(patterned(below - 1, 3), bucket);
        EXPECT_TRUE(refused(unpad(fits_below))) << bucket;
        const auto needs_this = padded_by_hand(patterned(below, 3), bucket);
        const auto unpadded = unpad(needs_this);
        ASSERT_TRUE(unpadded.has_value()) << bucket;
        EXPECT_EQ(unpadded->size(), below) << bucket;
    }
}

TEST(Padding, KeepsTrailingZerosAndMarkersOfTheMessage)
{
    const Bytes message{0x00, 0x80, 0x00, 0x80, 0x00};
    const auto padded = pad(message);
    ASSERT_TRUE(padded.has_value());
    const auto unpadded = unpad(*padded);
    ASSERT_TRUE(unpadded.has_value());
    EXPECT_EQ(copied(*unpadded), message);
}

TEST(Padding, RefusesAMessageTooLongForEveryBucket)
{
    const auto too_long = pad(patterned(largest_paddable_size + 1, 1));
    ASSERT_FALSE(too_long.has_value());
    EXPECT_EQ(too_long.error(), PaddingError::too_long);
    const auto longest = pad(patterned(largest_paddable_size, 1));
    ASSERT_TRUE(longest.has_value());
    EXPECT_EQ(longest->size(), 69632U);
}

TEST(Padding, RefusesALengthThatIsNotABucket)
{
    auto padded = padded_by_hand(patterned(10, 1), 2048);
    padded.push_back(0);
    EXPECT_TRUE(refused(unpad(padded)));
    padded.resize(2047);
    EXPECT_TRUE(refused(unpad(padded)));
    EXPECT_TRUE(refused(unpad(Bytes{})));
}

TEST(Padding, RefusesAMissingOrWrongMarker)
{
    EXPECT_TRUE(refused(unpad(Bytes(2048, 0))));
    auto padded = Bytes(2048, 0);
    padded.at(10) = 0x81;
    EXPECT_TRUE(refused(unpad(padded)));
    padded.at(10) = padding_marker;
    padded.at(2047) = 0x01;
    EXPECT_TRUE(refused(unpad(padded)));
}

TEST(Padding, RefusesABucketLargerThanTheMessageNeeds)
{
    EXPECT_TRUE(refused(unpad(padded_by_hand(patterned(10, 5), 4096))));
    EXPECT_TRUE(refused(unpad(padded_by_hand(patterned(65535, 5), 69632))));
}

TEST(Padding, AcceptsAMarkerAtTheLastByte)
{
    for (const auto bucket : padding_buckets) {
        const auto message = patterned(bucket - 1, 9);
        const auto padded = padded_by_hand(message, bucket);
        const auto unpadded = unpad(padded);
        ASSERT_TRUE(unpadded.has_value()) << bucket;
        EXPECT_EQ(copied(*unpadded), message) << bucket;
    }
}

RC_GTEST_PROP(PaddingProperties, RoundTripsAnyMessageThatFits, ())
{
    const auto size = *rc::gen::oneOf(rc::gen::inRange<std::size_t>(0, largest_paddable_size + 1), rc::gen::elementOf(edge_sizes()));
    const auto message = patterned(size, *rc::gen::arbitrary<std::uint32_t>());
    const auto padded = pad(message);
    RC_ASSERT(padded.has_value());
    RC_ASSERT(padded->size() == padded_size(size));
    const auto unpadded = unpad(*padded);
    RC_ASSERT(unpadded.has_value());
    RC_ASSERT(copied(*unpadded) == message);
}

RC_GTEST_PROP(PaddingProperties, AcceptsExactlyTheOutputsOfPad, ())
{
    const auto bucket = *rc::gen::elementOf(padding_buckets);
    const auto marker = *rc::gen::inRange<std::size_t>(0, bucket);
    auto input = padded_by_hand(patterned(marker, *rc::gen::arbitrary<std::uint32_t>()), bucket);
    if (*rc::gen::arbitrary<bool>()) {
        input.at(*rc::gen::inRange<std::size_t>(marker, bucket)) = *rc::gen::arbitrary<std::uint8_t>();
    }
    const auto unpadded = unpad(input);
    RC_ASSERT(unpadded.has_value() == reference_accepts(input));
    if (unpadded) {
        const auto again = pad(*unpadded);
        RC_ASSERT(again.has_value());
        RC_ASSERT(*again == input);
    }
}

}
}
