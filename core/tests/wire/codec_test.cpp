// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/codec.hpp"

#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lume::wire {
namespace {

using crypto::Bytes;

std::optional<std::uint32_t> next_code_point(const Bytes& text, std::size_t& position)
{
    const std::uint32_t lead = text.at(position);
    std::size_t length = 0;
    std::uint32_t value = 0;
    if (lead < 0x80) {
        length = 1;
        value = lead;
    } else if ((lead >> 5U) == 0x6) {
        length = 2;
        value = lead & 0x1fU;
    } else if ((lead >> 4U) == 0xe) {
        length = 3;
        value = lead & 0x0fU;
    } else if ((lead >> 3U) == 0x1e) {
        length = 4;
        value = lead & 0x07U;
    } else {
        return std::nullopt;
    }
    if (position + length > text.size()) {
        return std::nullopt;
    }
    for (std::size_t index = 1; index < length; ++index) {
        const std::uint32_t byte = text.at(position + index);
        if ((byte >> 6U) != 0x2) {
            return std::nullopt;
        }
        value = (value << 6U) | (byte & 0x3fU);
    }
    constexpr std::array<std::uint32_t, 5> smallest{0, 0, 0x80, 0x800, 0x10000};
    if (value < smallest.at(length) || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)
        || value == 0) {
        return std::nullopt;
    }
    position += length;
    return value;
}

bool reference_is_valid(const Bytes& text)
{
    std::size_t position = 0;
    while (position < text.size()) {
        if (!next_code_point(text, position)) {
            return false;
        }
    }
    return true;
}

Bytes encoded(std::uint32_t code_point)
{
    if (code_point < 0x80) {
        return {static_cast<std::uint8_t>(code_point)};
    }
    if (code_point < 0x800) {
        return {static_cast<std::uint8_t>(0xc0U | (code_point >> 6U)), static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
    }
    if (code_point < 0x10000) {
        return {static_cast<std::uint8_t>(0xe0U | (code_point >> 12U)),
            static_cast<std::uint8_t>(0x80U | ((code_point >> 6U) & 0x3fU)),
            static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
    }
    return {static_cast<std::uint8_t>(0xf0U | (code_point >> 18U)),
        static_cast<std::uint8_t>(0x80U | ((code_point >> 12U) & 0x3fU)),
        static_cast<std::uint8_t>(0x80U | ((code_point >> 6U) & 0x3fU)),
        static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
}

TEST(WireCodec, IntegersAreBigEndian)
{
    Writer writer;
    writer.u8(0x01).u16(0x0203).u32(0x04050607).u64(0x08090a0b0c0d0e0f);
    EXPECT_EQ(test::to_hex(writer.view()), "0102030405060708090a0b0c0d0e0f");
    Reader reader(writer.view());
    EXPECT_EQ(reader.u8(), std::uint8_t{0x01});
    EXPECT_EQ(reader.u16(), std::uint16_t{0x0203});
    EXPECT_EQ(reader.u32(), std::uint32_t{0x04050607});
    EXPECT_EQ(reader.u64(), std::uint64_t{0x08090a0b0c0d0e0f});
    EXPECT_TRUE(reader.finish().has_value());
}

TEST(WireCodec, ShortInputIsTruncated)
{
    const Bytes three{1, 2, 3};
    Reader reader(three);
    EXPECT_EQ(reader.u32().error(), Error::truncated);
    EXPECT_EQ(reader.remaining(), 3U);
    EXPECT_EQ(reader.fixed(4).error(), Error::truncated);
}

TEST(WireCodec, BooleansAndOptionalsAreOnlyZeroOrOne)
{
    const Bytes values{0, 1, 2, 255};
    Reader reader(values);
    EXPECT_EQ(reader.boolean(), false);
    EXPECT_EQ(reader.present(), true);
    EXPECT_EQ(reader.boolean().error(), Error::non_canonical);
    EXPECT_EQ(reader.present().error(), Error::non_canonical);
}

TEST(WireCodec, LengthsAndCountsAreBounded)
{
    const Bytes over_bound = Writer{}.u32(5).fixed(Bytes(5, 7)).take();
    EXPECT_EQ(Reader(over_bound).bytes(4).error(), Error::over_bound);
    EXPECT_EQ(Reader(over_bound).bytes(5).value().size(), 5U);
    const Bytes claims_more = Writer{}.u32(9).fixed(Bytes(5, 7)).take();
    EXPECT_EQ(Reader(claims_more).bytes(100).error(), Error::truncated);
    const Bytes huge_length = Writer{}.u32(std::numeric_limits<std::uint32_t>::max()).take();
    EXPECT_EQ(Reader(huge_length).bytes(std::numeric_limits<std::size_t>::max()).error(), Error::truncated);
    const Bytes count = Writer{}.u16(9).take();
    EXPECT_EQ(Reader(count).count(8).error(), Error::over_bound);
    EXPECT_EQ(Reader(count).count(9).value(), 9U);
}

TEST(WireCodec, TrailingBytesAreRejected)
{
    const Bytes value{0, 0, 0, 1, 9};
    Reader reader(value);
    EXPECT_EQ(reader.u32(), std::uint32_t{1});
    EXPECT_EQ(reader.finish().error(), Error::trailing_bytes);
}

TEST(WireCodec, TextAcceptsWellFormedUtf8)
{
    for (const auto& text : std::vector<Bytes>{
             {},
             {'a', 'b', 'c'},
             {0xc2, 0x80},
             {0xdf, 0xbf},
             {0xe0, 0xa0, 0x80},
             {0xed, 0x9f, 0xbf},
             {0xee, 0x80, 0x80},
             {0xef, 0xbf, 0xbf},
             {0xf0, 0x90, 0x80, 0x80},
             {0xf4, 0x8f, 0xbf, 0xbf},
             {0xd0, 0x9b, 0xd0, 0xa3, 0xd0, 0x9c, 0xd0, 0x95}}) {
        EXPECT_TRUE(is_valid_text(text)) << test::to_hex(text);
    }
    const Bytes encoded_text = Writer{}.text("LUME — ЛЮМЕ", 32).take();
    EXPECT_EQ(Reader(encoded_text).text(32).value(), "LUME — ЛЮМЕ");
}

TEST(WireCodec, TextRejectsEverythingElse)
{
    for (const auto& text : std::vector<Bytes>{
             {0x00},
             {'a', 0x00},
             {0x80},
             {0xbf},
             {0xc0, 0x80},
             {0xc1, 0xbf},
             {0xc2},
             {0xe0, 0x80, 0x80},
             {0xe0, 0x9f, 0xbf},
             {0xed, 0xa0, 0x80},
             {0xed, 0xbf, 0xbf},
             {0xf0, 0x80, 0x80, 0x80},
             {0xf0, 0x8f, 0xbf, 0xbf},
             {0xf4, 0x90, 0x80, 0x80},
             {0xf5, 0x80, 0x80, 0x80},
             {0xff},
             {0xe2, 0x82},
             {0xf0, 0x9f, 0x98}}) {
        EXPECT_FALSE(is_valid_text(text)) << test::to_hex(text);
    }
    const Bytes encoded_text = Writer{}.bytes(Bytes{0xc0, 0x80}, 8).take();
    EXPECT_EQ(Reader(encoded_text).text(8).error(), Error::invalid_text);
}

TEST(WireCodec, WritingPastABoundIsAProgrammingError)
{
    Writer writer;
    EXPECT_THROW(writer.bytes(Bytes(9), 8), std::length_error);
    EXPECT_THROW(writer.count(9, 8), std::length_error);
    EXPECT_THROW(writer.count(70000, 100000), std::length_error);
    EXPECT_THROW(writer.text(std::string(1, '\0'), 8), std::invalid_argument);
    EXPECT_TRUE(writer.view().empty());
}

RC_GTEST_PROP(WireCodecProperties, IntegersRoundTrip, (std::uint8_t a, std::uint16_t b, std::uint32_t c, std::uint64_t d))
{
    const auto bytes = Writer{}.u8(a).u16(b).u32(c).u64(d).take();
    Reader reader(bytes);
    RC_ASSERT(reader.u8().value() == a);
    RC_ASSERT(reader.u16().value() == b);
    RC_ASSERT(reader.u32().value() == c);
    RC_ASSERT(reader.u64().value() == d);
    RC_ASSERT(reader.finish().has_value());
}

RC_GTEST_PROP(WireCodecProperties, TextValidationMatchesAReferenceDecoder, (const Bytes& text))
{
    RC_ASSERT(is_valid_text(text) == reference_is_valid(text));
}

RC_GTEST_PROP(WireCodecProperties, EncodedCodePointsAreValidText, ())
{
    const auto code_points = *rc::gen::container<std::vector<std::uint32_t>>(rc::gen::oneOf(
        rc::gen::inRange<std::uint32_t>(1, 0xd800), rc::gen::inRange<std::uint32_t>(0xe000, 0x110000)));
    Bytes text;
    for (const auto code_point : code_points) {
        const auto bytes = encoded(code_point);
        text.insert(text.end(), bytes.begin(), bytes.end());
    }
    RC_ASSERT(is_valid_text(text));
}

RC_GTEST_PROP(WireCodecProperties, BytesRoundTripWithinTheirBound, (const Bytes& value))
{
    const auto bytes = Writer{}.bytes(value, value.size()).take();
    Reader reader(bytes);
    const auto read = reader.bytes(value.size());
    RC_ASSERT(read.has_value());
    RC_ASSERT(Bytes(read->begin(), read->end()) == value);
    RC_ASSERT(reader.finish().has_value());
    if (!value.empty()) {
        RC_ASSERT(Reader(bytes).bytes(value.size() - 1).error() == Error::over_bound);
    }
}

}
}
