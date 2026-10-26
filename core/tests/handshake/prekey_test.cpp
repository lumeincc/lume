// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/handshake/prekey.hpp"

#include "lume/identity/phrase.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace lume::handshake {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

identity::Identity owner_from(const Bytes& entropy)
{
    auto owner = identity::derive_identity(SecretBytes::copy_of(entropy));
    if (!owner) {
        throw std::runtime_error("deriving an identity failed");
    }
    return std::move(*owner);
}

TEST(Prekey, TheMessageIsLabelledAndCoversTheGeneration)
{
    const Bytes key(32, 0xab);
    const auto message = prekey_message(
        PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 0x01020304, .created_at = 0x05060708090a0b0c, .generation = 7},
        key);
    EXPECT_EQ(
        test::to_hex(message),
        test::to_hex(crypto::label("prekey")) + "04" + "01020304" + "05060708090a0b0c" + "00000007" + "00000020"
            + test::to_hex(key));
}

TEST(Prekey, OneTimeKeysAreUnsignedAndEverythingElseIsSigned)
{
    const auto owner = owner_from(Bytes(identity::entropy_size, 1));
    const Bytes x_key(32, 3);
    const auto one_time = make_prekey_x(
        owner, PrekeyFacts{.kind = wire::PrekeyKind::one_time_prekey, .id = 1, .created_at = 10, .generation = 1}, x_key);
    ASSERT_TRUE(one_time.has_value());
    EXPECT_FALSE(one_time->signature.has_value());
    EXPECT_TRUE(verify_prekey(owner.signing.public_key, *one_time, 1));

    const auto seal = make_prekey_x(
        owner, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 2, .created_at = 10, .generation = 1}, x_key);
    ASSERT_TRUE(seal.has_value());
    ASSERT_TRUE(seal->signature.has_value());
    EXPECT_TRUE(verify_prekey(owner.signing.public_key, *seal, 1));
    EXPECT_FALSE(verify_prekey(owner.signing.public_key, *seal, 2));
    EXPECT_FALSE(verify_prekey(owner.signing.public_key, *seal, 0));

    auto stripped = *seal;
    stripped.signature.reset();
    EXPECT_FALSE(verify_prekey(owner.signing.public_key, stripped, 1));
}

TEST(Prekey, RefusesWrongKindsSizesAndGenerationZero)
{
    const auto owner = owner_from(Bytes(identity::entropy_size, 2));
    EXPECT_EQ(
        make_prekey_x(owner, PrekeyFacts{.kind = wire::PrekeyKind::kem_one_time, .id = 1, .created_at = 1, .generation = 1}, Bytes(32))
            .error(),
        crypto::Error::invalid_key);
    EXPECT_EQ(
        make_prekey_kem(owner, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 1, .created_at = 1, .generation = 1}, Bytes(1184))
            .error(),
        crypto::Error::invalid_key);
    EXPECT_EQ(
        make_prekey_x(owner, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 1, .created_at = 1, .generation = 1}, Bytes(31))
            .error(),
        crypto::Error::invalid_size);
    EXPECT_EQ(
        make_prekey_kem(owner, PrekeyFacts{.kind = wire::PrekeyKind::kem_last_resort, .id = 1, .created_at = 1, .generation = 1}, Bytes(32))
            .error(),
        crypto::Error::invalid_size);
    EXPECT_EQ(
        make_prekey_x(owner, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 1, .created_at = 1, .generation = 0}, Bytes(32))
            .error(),
        crypto::Error::out_of_range);
}

TEST(Prekey, UsableWindowsFollowTheKind)
{
    constexpr std::uint64_t at = 1'000'000;
    for (const auto kind : {wire::PrekeyKind::signed_prekey, wire::PrekeyKind::kem_last_resort, wire::PrekeyKind::seal_key}) {
        EXPECT_TRUE(is_rotating(kind));
        EXPECT_TRUE(is_usable_at(kind, at, at));
        EXPECT_TRUE(is_usable_at(kind, at, at + rotating_key_usable_for));
        EXPECT_FALSE(is_usable_at(kind, at, at + rotating_key_usable_for + 1));
        EXPECT_TRUE(is_usable_at(kind, at + allowed_clock_skew, at));
        EXPECT_FALSE(is_usable_at(kind, at + allowed_clock_skew + 1, at));
    }
    for (const auto kind : {wire::PrekeyKind::kem_one_time, wire::PrekeyKind::one_time_prekey}) {
        EXPECT_FALSE(is_rotating(kind));
        EXPECT_TRUE(is_usable_at(kind, at, at + (1000 * rotating_key_usable_for)));
        EXPECT_FALSE(is_usable_at(kind, at + allowed_clock_skew + 1, at));
    }
}

RC_GTEST_PROP(PrekeyProperties, ASignatureCoversEveryFact, ())
{
    const auto owner = owner_from(test::random_bytes_of(identity::entropy_size));
    const PrekeyFacts facts{
        .kind = *rc::gen::element(wire::PrekeyKind::signed_prekey, wire::PrekeyKind::seal_key),
        .id = *rc::gen::arbitrary<std::uint32_t>(),
        .created_at = *rc::gen::arbitrary<std::uint64_t>(),
        .generation = *rc::gen::inRange<std::uint32_t>(1, 1000)};
    const auto key = test::random_bytes_of(32);
    const auto prekey = make_prekey_x(owner, facts, key);
    RC_ASSERT(prekey.has_value());
    RC_ASSERT(verify_prekey(owner.signing.public_key, *prekey, facts.generation));

    auto other_id = *prekey;
    other_id.id ^= 1U;
    RC_ASSERT_FALSE(verify_prekey(owner.signing.public_key, other_id, facts.generation));
    auto other_time = *prekey;
    other_time.created_at ^= 1U;
    RC_ASSERT_FALSE(verify_prekey(owner.signing.public_key, other_time, facts.generation));
    auto other_kind = *prekey;
    other_kind.kind = facts.kind == wire::PrekeyKind::seal_key ? wire::PrekeyKind::signed_prekey : wire::PrekeyKind::seal_key;
    RC_ASSERT_FALSE(verify_prekey(owner.signing.public_key, other_kind, facts.generation));
    RC_ASSERT_FALSE(verify_prekey(owner.signing.public_key, *prekey, facts.generation + 1));
    auto other_key = *prekey;
    const auto flipped = test::flip_random_bit(other_key.key);
    std::ranges::copy(flipped, other_key.key.begin());
    RC_ASSERT_FALSE(verify_prekey(owner.signing.public_key, other_key, facts.generation));
}

}
}
