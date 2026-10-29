// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/structures.hpp"

#include "support/expected.hpp"
#include "support/mutate.hpp"
#include "support/utf8.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

UsernameCertificate random_username_certificate()
{
    UsernameCertificate value;
    value.key_id = any_integer<std::uint32_t>();
    const auto code_points = *rc::gen::container<std::vector<std::uint32_t>>(rc::gen::oneOf(
        rc::gen::inRange<std::uint32_t>(1, 0xd800), rc::gen::inRange<std::uint32_t>(0xe000, 0x110000)));
    for (const auto code_point : code_points) {
        const auto bytes = test::utf8_of(code_point);
        if (value.username.size() + bytes.size() > username_bound) {
            break;
        }
        value.username.append(bytes.begin(), bytes.end());
    }
    value.account_id = random_array<account_id_size>();
    value.ik_sig = random_array<ed25519_key_size>();
    value.ik_dh = random_array<x25519_key_size>();
    value.generation = any_integer<std::uint32_t>();
    value.issued_at = any_integer<std::uint64_t>();
    value.expires_at = any_integer<std::uint64_t>();
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

Introduction random_introduction()
{
    Introduction value;
    value.account_id = random_array<account_id_size>();
    value.generation = any_integer<std::uint32_t>();
    value.token = random_array<token_size>();
    value.seal_key.id = any_integer<std::uint32_t>();
    value.seal_key.created_at = any_integer<std::uint64_t>();
    value.seal_key.key = random_array<x25519_key_size>();
    value.seal_key.signature = random_array<signature_size>();
    if (*rc::gen::arbitrary<bool>()) {
        value.certificate = random_username_certificate();
    }
    return value;
}

Content random_content()
{
    Content value;
    value.id = random_array<content_id_size>();
    value.kind = *rc::gen::arbitrary<std::uint8_t>();
    if (*rc::gen::arbitrary<bool>()) {
        value.introduction = random_introduction();
    }
    value.body = *rc::gen::container<Bytes>(rc::gen::arbitrary<std::uint8_t>());
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

Content content_with_body(std::size_t size)
{
    Content value;
    value.body = Bytes(size);
    return value;
}

UsernameCertificate certificate_named(std::string username)
{
    UsernameCertificate value;
    value.username = std::move(username);
    return value;
}

Bytes with_username_bytes(const Bytes& username)
{
    auto encoded = Writer{}.u32(0).u32(static_cast<std::uint32_t>(username.size())).take();
    encoded.insert(encoded.end(), username.begin(), username.end());
    const auto rest = encode(UsernameCertificate{});
    const auto after_username = crypto::ByteView(rest).subspan(4 + 4);
    encoded.insert(encoded.end(), after_username.begin(), after_username.end());
    return encoded;
}

constexpr std::size_t introduction_seal_key_offset = account_id_size + 4 + token_size;

TEST(WireStructures, FixedSizesMatchTheProtocol)
{
    EXPECT_EQ(encode(RatchetHeader{}).size(), 40U);
    EXPECT_EQ(24 + encode(RatchetHeader{}).size() + 16, encrypted_header_size);
    EXPECT_EQ(encode(one_time_prekey()).size(), 1U + 4 + 8 + 32 + 1);
    EXPECT_EQ(encode(signed_prekey()).size(), 1U + 4 + 8 + 32 + 1 + 64);
    EXPECT_EQ(encode(PrekeyKem{}).size(), 1U + 4 + 8 + 1184 + 64);
    EXPECT_EQ(encode(InitialHeader{}).size(), 32U + 32 + 64 + 32 + 1088 + 4 + 1 + 4 + 1);
    EXPECT_EQ(encode(seal_with_box(seal_box_bound)).size(), 1U + 4 + 32 + 24 + 4 + seal_box_bound);
    EXPECT_EQ(encode(UsernameCertificate{}).size(), 4U + 4 + 16 + 32 + 32 + 4 + 8 + 8 + 64);
    EXPECT_EQ(encode(Introduction{}).size(), 16U + 4 + 32 + encode(signed_prekey()).size() + 1);
    EXPECT_EQ(encode(Content{}).size(), 16U + 1 + 1 + 4);
}

TEST(WireStructures, ContentFieldsAreInProtocolOrder)
{
    Content content;
    content.id.fill(0x11);
    content.kind = 7;
    content.body = {0x68, 0x69};
    EXPECT_EQ(test::to_hex(encode(content)), "11111111111111111111111111111111" "07" "00" "00000002" "6869");

    Introduction introduction;
    introduction.account_id.fill(0x22);
    introduction.generation = 3;
    introduction.token.fill(0x33);
    introduction.seal_key.id = 5;
    introduction.seal_key.created_at = 6;
    introduction.certificate = certificate_named("ab");
    introduction.certificate->key_id = 9;
    content.introduction = introduction;
    const auto encoded = encode(content);
    const std::string expected_prefix = "11111111111111111111111111111111" "07" "01"
                                        "22222222222222222222222222222222" "00000003"
                                        "3333333333333333333333333333333333333333333333333333333333333333"
                                        "04" "00000005" "0000000000000006";
    EXPECT_EQ(test::to_hex(encoded).substr(0, expected_prefix.size()), expected_prefix);
    const auto certificate_at = content_id_size + 1 + 1 + introduction_seal_key_offset + encode(signed_prekey()).size();
    EXPECT_EQ(test::to_hex(crypto::ByteView(encoded).subspan(certificate_at, 1 + 4 + 4 + 2)), "01" "00000009" "00000002" "6162");
    EXPECT_EQ(test::to_hex(crypto::ByteView(encoded).last(6)), "00000002" "6869");
    EXPECT_EQ(decode(encoded, read_content), content);
}

TEST(WireStructures, IntroductionsCarryOnlySealKeys)
{
    auto introduction = encode(Introduction{});
    for (const int kind : {0, 1, 2, 3, 5, 6, 255}) {
        introduction.at(introduction_seal_key_offset) = static_cast<std::uint8_t>(kind);
        EXPECT_EQ(test::error_of(decode(introduction, read_introduction)), Error::invalid_value) << kind;
    }
    EXPECT_TRUE(decode(encode(Introduction{}), read_introduction).has_value());
}

TEST(WireStructures, WritersRefuseWhatTheirReadersRefuse)
{
    auto signed_one_time = signed_prekey();
    signed_one_time.kind = PrekeyKind::one_time_prekey;
    EXPECT_THROW((void)encode(signed_one_time), std::invalid_argument);
    auto unsigned_signed = one_time_prekey();
    unsigned_signed.kind = PrekeyKind::signed_prekey;
    EXPECT_THROW((void)encode(unsigned_signed), std::invalid_argument);
    auto kem_kind = signed_prekey();
    kem_kind.kind = PrekeyKind::kem_last_resort;
    EXPECT_THROW((void)encode(kem_kind), std::invalid_argument);

    PrekeyKem x25519_kind;
    x25519_kind.kind = PrekeyKind::signed_prekey;
    EXPECT_THROW((void)encode(x25519_kind), std::invalid_argument);
    InitialHeader header;
    header.pq_kind = PrekeyKind::seal_key;
    EXPECT_THROW((void)encode(header), std::invalid_argument);

    Introduction signed_prekey_instead;
    signed_prekey_instead.seal_key.kind = PrekeyKind::signed_prekey;
    EXPECT_THROW((void)encode(signed_prekey_instead), std::invalid_argument);
    Content content;
    content.introduction = signed_prekey_instead;
    EXPECT_THROW((void)encode(content), std::invalid_argument);
}

TEST(WireStructures, UsernamesAreBoundedText)
{
    EXPECT_TRUE(decode(encode(certificate_named(std::string(username_bound, 'a'))), read_username_certificate).has_value());
    EXPECT_THROW((void)encode(certificate_named(std::string(username_bound + 1, 'a'))), std::length_error);
    EXPECT_THROW((void)encode(certificate_named(std::string("a\0b", 3))), std::invalid_argument);
    EXPECT_EQ(test::error_of(decode(with_username_bytes(Bytes(username_bound + 1, 'a')), read_username_certificate)),
        Error::over_bound);
    EXPECT_EQ(test::error_of(decode(with_username_bytes({'a', 0x00, 'b'}), read_username_certificate)), Error::invalid_text);
    EXPECT_EQ(test::error_of(decode(with_username_bytes({'a', 0xC3}), read_username_certificate)), Error::invalid_text);
    const auto accented = decode(with_username_bytes({0xC3, 0xA9}), read_username_certificate);
    ASSERT_TRUE(accented.has_value());
    EXPECT_EQ(accented->username, "\xC3\xA9");
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
    EXPECT_TRUE(decode(encode(content_with_body(content_body_bound)), read_content).has_value());
    EXPECT_THROW((void)encode(content_with_body(content_body_bound + 1)), std::length_error);
    auto content = Writer{}.fixed(Bytes(content_id_size)).u8(0).present(false).u32(content_body_bound + 1).take();
    content.resize(content.size() + content_body_bound + 1);
    EXPECT_EQ(test::error_of(decode(content, read_content)), Error::over_bound);
}

TEST(WireStructures, NonCanonicalOptionalsAreRejected)
{
    auto inner = encode(Inner{});
    inner.at(ed25519_key_size) = 2;
    EXPECT_EQ(decode(inner, read_inner).error(), Error::non_canonical);
    auto header = encode(InitialHeader{});
    header.back() = 2;
    EXPECT_EQ(decode(header, read_initial_header).error(), Error::non_canonical);
    auto content = encode(Content{});
    content.at(content_id_size + 1) = 2;
    EXPECT_EQ(test::error_of(decode(content, read_content)), Error::non_canonical);
    auto introduction = encode(Introduction{});
    introduction.back() = 2;
    EXPECT_EQ(test::error_of(decode(introduction, read_introduction)), Error::non_canonical);
}

RC_GTEST_PROP(WireStructureProperties, PrekeyXRoundTrips, ())
{
    check_round_trip(random_prekey_x(), read_prekey_x);
}

RC_GTEST_PROP(WireStructureProperties, PrekeyKemRoundTrips, ())
{
    check_round_trip(random_prekey_kem(), read_prekey_kem);
}

RC_GTEST_PROP(WireStructureProperties, UsernameCertificateRoundTrips, ())
{
    check_round_trip(random_username_certificate(), read_username_certificate);
}

RC_GTEST_PROP(WireStructureProperties, IntroductionRoundTrips, ())
{
    check_round_trip(random_introduction(), read_introduction);
}

RC_GTEST_PROP(WireStructureProperties, ContentRoundTrips, ())
{
    check_round_trip(random_content(), read_content);
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
    check(read_username_certificate);
    check(read_introduction);
    check(read_content);
}

}
}
