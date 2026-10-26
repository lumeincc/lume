// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/structures.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>

namespace lume::wire {
namespace {

using crypto::Bytes;

template <std::size_t Size>
crypto::ByteArray<Size> random_array()
{
    const auto bytes = test::random_bytes_of(Size);
    crypto::ByteArray<Size> array{};
    std::ranges::copy(bytes, array.begin());
    return array;
}

template <typename T>
T any_integer()
{
    return *rc::gen::resize(rc::kNominalSize, rc::gen::arbitrary<T>());
}

PrekeyX random_prekey_x()
{
    PrekeyX value;
    value.kind = *rc::gen::element(PrekeyKind::signed_prekey, PrekeyKind::seal_key, PrekeyKind::one_time_prekey);
    value.id = any_integer<std::uint32_t>();
    value.created_at = any_integer<std::uint64_t>();
    value.key = random_array<x25519_key_size>();
    if (value.kind != PrekeyKind::one_time_prekey) {
        value.signature = random_array<signature_size>();
    }
    return value;
}

PrekeyKem random_prekey_kem()
{
    PrekeyKem value;
    value.kind = *rc::gen::element(PrekeyKind::kem_last_resort, PrekeyKind::kem_one_time);
    value.id = any_integer<std::uint32_t>();
    value.created_at = any_integer<std::uint64_t>();
    value.key = random_array<kem_public_key_size>();
    value.signature = random_array<signature_size>();
    return value;
}

InitialHeader random_initial_header()
{
    InitialHeader value;
    value.ik_sig = random_array<ed25519_key_size>();
    value.ik_dh = random_array<x25519_key_size>();
    value.bind = random_array<signature_size>();
    value.ephemeral_key = random_array<x25519_key_size>();
    value.kem_ciphertext = random_array<kem_ciphertext_size>();
    value.spk_id = any_integer<std::uint32_t>();
    value.pq_kind = *rc::gen::element(PrekeyKind::kem_last_resort, PrekeyKind::kem_one_time);
    value.pq_id = any_integer<std::uint32_t>();
    if (*rc::gen::arbitrary<bool>()) {
        value.opk_id = any_integer<std::uint32_t>();
    }
    return value;
}

RatchetMessage random_ratchet_message()
{
    RatchetMessage value;
    value.encrypted_header = random_array<encrypted_header_size>();
    value.body = *rc::gen::container<Bytes>(rc::gen::arbitrary<std::uint8_t>());
    return value;
}

Inner random_inner()
{
    Inner value;
    value.sender = random_array<ed25519_key_size>();
    if (*rc::gen::arbitrary<bool>()) {
        value.initial = random_initial_header();
    }
    value.message = random_ratchet_message();
    return value;
}

Seal random_seal()
{
    Seal value;
    value.ssk_id = any_integer<std::uint32_t>();
    value.ephemeral_key = random_array<x25519_key_size>();
    value.nonce = random_array<nonce_size>();
    value.box = *rc::gen::container<Bytes>(rc::gen::arbitrary<std::uint8_t>());
    return value;
}

template <typename T, typename Read>
void check_round_trip(const T& value, Read read)
{
    const auto bytes = encode(value);
    const auto decoded = decode(bytes, read);
    RC_ASSERT(decoded.has_value());
    RC_ASSERT(*decoded == value);
    RC_ASSERT(encode(*decoded) == bytes);

    const auto cut = *rc::gen::inRange<std::size_t>(0, bytes.size());
    RC_ASSERT_FALSE(decode(crypto::ByteView(bytes).first(cut), read).has_value());

    Bytes longer(bytes);
    longer.push_back(*rc::gen::arbitrary<std::uint8_t>());
    const auto with_trailing = decode(longer, read);
    RC_ASSERT_FALSE(with_trailing.has_value());
    RC_ASSERT(with_trailing.error() == Error::trailing_bytes);
}

PrekeyX one_time_prekey()
{
    PrekeyX value;
    value.kind = PrekeyKind::one_time_prekey;
    return value;
}

PrekeyX signed_prekey()
{
    PrekeyX value;
    value.signature = crypto::ByteArray<signature_size>{};
    return value;
}

Seal seal_with_box(std::size_t size)
{
    Seal value;
    value.box = Bytes(size);
    return value;
}

RatchetMessage message_with_body(std::size_t size)
{
    RatchetMessage value;
    value.body = Bytes(size);
    return value;
}

TEST(WireStructures, FixedSizesMatchTheProtocol)
{
    EXPECT_EQ(encode(RatchetHeader{}).size(), 40U);
    EXPECT_EQ(24 + encode(RatchetHeader{}).size() + 16, encrypted_header_size);
    EXPECT_EQ(encode(one_time_prekey()).size(), 1U + 4 + 8 + 32 + 1);
    EXPECT_EQ(encode(signed_prekey()).size(), 1U + 4 + 8 + 32 + 1 + 64);
    EXPECT_EQ(encode(PrekeyKem{}).size(), 1U + 4 + 8 + 1184 + 64);
    EXPECT_EQ(encode(InitialHeader{}).size(), 32U + 32 + 64 + 32 + 1088 + 4 + 1 + 4 + 1);
    EXPECT_EQ(encode(seal_with_box(seal_box_bound)).size(), 1U + 4 + 32 + 24 + 4 + seal_box_bound);
}

TEST(WireStructures, PrekeySignaturesFollowTheKind)
{
    auto unsigned_signed_prekey = encode(one_time_prekey());
    unsigned_signed_prekey.front() = static_cast<std::uint8_t>(PrekeyKind::signed_prekey);
    EXPECT_EQ(decode(unsigned_signed_prekey, read_prekey_x).error(), Error::invalid_value);

    auto signed_one_time = encode(signed_prekey());
    signed_one_time.front() = static_cast<std::uint8_t>(PrekeyKind::one_time_prekey);
    EXPECT_EQ(decode(signed_one_time, read_prekey_x).error(), Error::invalid_value);
}

TEST(WireStructures, KindsOutsideTheirStructureAreRejected)
{
    for (const int kind : {0, 2, 3, 6, 255}) {
        auto prekey = encode(signed_prekey());
        prekey.front() = static_cast<std::uint8_t>(kind);
        EXPECT_EQ(decode(prekey, read_prekey_x).error(), Error::invalid_value) << kind;
    }
    for (const int kind : {0, 1, 4, 5, 255}) {
        auto prekey = encode(PrekeyKem{});
        prekey.front() = static_cast<std::uint8_t>(kind);
        EXPECT_EQ(decode(prekey, read_prekey_kem).error(), Error::invalid_value) << kind;
    }
    auto header = encode(InitialHeader{});
    header.at(32 + 32 + 64 + 32 + 1088 + 4) = static_cast<std::uint8_t>(PrekeyKind::signed_prekey);
    EXPECT_EQ(decode(header, read_initial_header).error(), Error::invalid_value);
}

TEST(WireStructures, OnlySealVersionOneIsAccepted)
{
    auto seal = encode(Seal{});
    for (const int version : {0, 2, 255}) {
        seal.front() = static_cast<std::uint8_t>(version);
        EXPECT_EQ(decode(seal, read_seal).error(), Error::unsupported_version) << version;
    }
}

TEST(WireStructures, BodiesAreBounded)
{
    EXPECT_THROW((void)encode(message_with_body(ratchet_body_bound + 1)), std::length_error);
    EXPECT_THROW((void)encode(seal_with_box(seal_box_bound + 1)), std::length_error);
    auto message = Writer{}.fixed(Bytes(encrypted_header_size)).u32(ratchet_body_bound + 1).take();
    message.resize(message.size() + ratchet_body_bound + 1);
    EXPECT_EQ(decode(message, read_ratchet_message).error(), Error::over_bound);
}

TEST(WireStructures, NonCanonicalOptionalsAreRejected)
{
    auto inner = encode(Inner{});
    inner.at(ed25519_key_size) = 2;
    EXPECT_EQ(decode(inner, read_inner).error(), Error::non_canonical);
    auto header = encode(InitialHeader{});
    header.back() = 2;
    EXPECT_EQ(decode(header, read_initial_header).error(), Error::non_canonical);
}

RC_GTEST_PROP(WireStructureProperties, PrekeyXRoundTrips, ())
{
    check_round_trip(random_prekey_x(), read_prekey_x);
}

RC_GTEST_PROP(WireStructureProperties, PrekeyKemRoundTrips, ())
{
    check_round_trip(random_prekey_kem(), read_prekey_kem);
}

RC_GTEST_PROP(WireStructureProperties, InitialHeaderRoundTrips, ())
{
    check_round_trip(random_initial_header(), read_initial_header);
}

RC_GTEST_PROP(WireStructureProperties, RatchetHeaderRoundTrips, ())
{
    check_round_trip(
        RatchetHeader{
            .ratchet_key = random_array<x25519_key_size>(),
            .previous_chain_length = any_integer<std::uint32_t>(),
            .message_number = any_integer<std::uint32_t>()},
        read_ratchet_header);
}

RC_GTEST_PROP(WireStructureProperties, RatchetMessageRoundTrips, ())
{
    check_round_trip(random_ratchet_message(), read_ratchet_message);
}

RC_GTEST_PROP(WireStructureProperties, InnerRoundTrips, ())
{
    check_round_trip(random_inner(), read_inner);
}

RC_GTEST_PROP(WireStructureProperties, SealRoundTrips, ())
{
    check_round_trip(random_seal(), read_seal);
}

RC_GTEST_PROP(WireStructureProperties, ArbitraryBytesDecodeOnlyToTheirOwnEncoding, (const Bytes& input))
{
    const auto check = [&input](auto read) {
        const auto decoded = decode(input, read);
        if (decoded) {
            RC_ASSERT(encode(*decoded) == input);
        }
    };
    check(read_prekey_x);
    check(read_prekey_kem);
    check(read_initial_header);
    check(read_ratchet_header);
    check(read_ratchet_message);
    check(read_inner);
    check(read_seal);
}

}
}
