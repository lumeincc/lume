// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "crypto/padding.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace lume::crypto {
namespace {

constexpr std::array<std::size_t, 3> buckets{4, 8, 16};

Bytes padded(ByteView message)
{
    const auto size = detail::padded_size(message.size(), buckets);
    if (!size) {
        return {};
    }
    Bytes out(*size, 0xee);
    if (!detail::pad_into(message, out, buckets)) {
        return {};
    }
    return out;
}

std::optional<Bytes> unpadded(ByteView candidate, std::span<const std::size_t> list = buckets)
{
    const auto message = detail::unpad(candidate, list);
    if (!message) {
        return std::nullopt;
    }
    return Bytes(message->begin(), message->end());
}

std::size_t smallest_bucket_for(std::size_t size)
{
    for (const auto bucket : buckets) {
        if (size < bucket) {
            return bucket;
        }
    }
    return 0;
}

TEST(BucketPadding, ChoosesTheSmallestBucketWithRoomForTheMarker)
{
    EXPECT_EQ(smallest_bucket_for(3), 4U);
    EXPECT_EQ(smallest_bucket_for(4), 8U);
    EXPECT_EQ(smallest_bucket_for(15), 16U);
    for (std::size_t size = 0; size < 16; ++size) {
        EXPECT_EQ(detail::padded_size(size, buckets), smallest_bucket_for(size)) << size;
    }
    EXPECT_FALSE(detail::padded_size(16, buckets).has_value());
    EXPECT_FALSE(detail::padded_size(0, std::span<const std::size_t>{}).has_value());
    constexpr std::array<std::size_t, 1> single{1195};
    EXPECT_EQ(detail::padded_size(1194, single), 1195U);
    EXPECT_FALSE(detail::padded_size(1195, single).has_value());
}

TEST(BucketPadding, WritesTheMessageTheMarkerAndZerosOverWhateverWasThere)
{
    EXPECT_EQ(padded(Bytes{1, 2, 3}), (Bytes{1, 2, 3, detail::padding_marker}));
    EXPECT_EQ(padded(Bytes{1, 2, 3, 4}), (Bytes{1, 2, 3, 4, detail::padding_marker, 0, 0, 0}));
    EXPECT_EQ(padded(Bytes{}), (Bytes{detail::padding_marker, 0, 0, 0}));
    Bytes wrong(8, 0xee);
    EXPECT_FALSE(detail::pad_into(Bytes{1}, wrong, buckets));
    EXPECT_EQ(wrong, Bytes(8, 0xee));
    Bytes short_by_one(3);
    EXPECT_FALSE(detail::pad_into(Bytes{1}, short_by_one, buckets));
    Bytes none(16);
    EXPECT_FALSE(detail::pad_into(Bytes(16, 1), none, buckets));
}

TEST(BucketPadding, UnpadsOnlyWhatPadWrites)
{
    for (std::size_t size = 0; size < 16; ++size) {
        const Bytes message(size, 0);
        EXPECT_EQ(unpadded(padded(message)), message) << size;
    }
    const Bytes markers{detail::padding_marker, detail::padding_marker, 0, detail::padding_marker};
    EXPECT_EQ(unpadded(markers), (Bytes{detail::padding_marker, detail::padding_marker, 0}));

    EXPECT_FALSE(detail::unpad(Bytes{1, 2, detail::padding_marker}, buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes(4, 0), buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes{}, buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes{1, 2, 3, 0x81}, buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes{1, 2, 3, 0x01}, buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes{1, detail::padding_marker, 0, 0, 0, 0, 0, 0}, buckets).has_value());
    EXPECT_TRUE(detail::unpad(Bytes{1, 2, 3, 4, detail::padding_marker, 0, 0, 0}, buckets).has_value());
    EXPECT_FALSE(detail::unpad(Bytes{detail::padding_marker}, std::span<const std::size_t>{}).has_value());
}

RC_GTEST_PROP(BucketPaddingProperties, RoundTripsAnyMessageThatFits, ())
{
    const auto message = *rc::gen::container<Bytes>(*rc::gen::inRange<std::size_t>(0, 16), rc::gen::arbitrary<std::uint8_t>());
    const auto out = padded(message);
    RC_ASSERT(out.size() == detail::padded_size(message.size(), buckets));
    RC_ASSERT(unpadded(out) == message);
}

RC_GTEST_PROP(BucketPaddingProperties, AcceptsOnlyTheOutputsOfPad, ())
{
    const auto size = *rc::gen::element(std::size_t{4}, std::size_t{8}, std::size_t{16}, std::size_t{5});
    const auto candidate = *rc::gen::container<Bytes>(size, rc::gen::element(std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{1}, detail::padding_marker));
    const auto message = unpadded(candidate);
    if (message) {
        RC_ASSERT(padded(*message) == candidate);
    }
}

}
}
