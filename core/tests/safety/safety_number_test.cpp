// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/safety/safety_number.hpp"

#include "lume/identity/phrase.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace lume::safety {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;
using identity::PublicIdentity;

std::vector<PublicIdentity> vector_identities()
{
    const auto cases = test::load_vectors("lume/identity.json").at("cases");
    std::vector<PublicIdentity> identities;
    for (const auto& vector : cases) {
        const auto entropy = test::from_hex(vector.at("entropy").get<std::string>());
        auto derived = identity::derive_identity(SecretBytes::copy_of(entropy));
        if (!derived) {
            throw std::runtime_error("deriving a vector identity failed");
        }
        identities.push_back(identity::public_identity(*derived));
    }
    return identities;
}

PublicIdentity random_identity()
{
    auto derived = identity::derive_identity(SecretBytes::copy_of(test::random_bytes_of(identity::entropy_size)));
    RC_ASSERT(derived.has_value());
    return identity::public_identity(*derived);
}

bool all_digits(const std::string& text)
{
    return std::ranges::all_of(text, [](char character) { return character >= '0' && character <= '9'; });
}

TEST(SafetyNumber, MatchesTheLumeVectors)
{
    const auto identities = vector_identities();
    const auto vectors = test::load_vectors("lume/safety.json");
    ASSERT_EQ(vectors.at("identities").size(), identities.size());
    for (const auto& expected : vectors.at("identities")) {
        const auto& subject = identities.at(expected.at("identity").get<std::size_t>());
        EXPECT_EQ(fingerprint(subject), expected.at("fingerprint").get<std::string>());
        EXPECT_EQ(test::to_hex(invite_fingerprint(subject)), expected.at("invite_fingerprint").get<std::string>());
        EXPECT_TRUE(matches_invite(subject, test::from_hex(expected.at("invite_fingerprint").get<std::string>())));
    }
    int checked = 0;
    for (const auto& pair : vectors.at("pairs")) {
        const auto& first = identities.at(pair.at("first").get<std::size_t>());
        const auto& second = identities.at(pair.at("second").get<std::size_t>());
        EXPECT_EQ(safety_number(first, second), pair.at("safety_number").get<std::string>());
        ++checked;
    }
    EXPECT_EQ(checked, 24);
}

TEST(SafetyNumber, HasThePublishedShape)
{
    const auto identities = vector_identities();
    const auto digits = fingerprint(identities.at(0));
    EXPECT_EQ(digits.size(), fingerprint_digits);
    EXPECT_TRUE(all_digits(digits));
    const auto number = safety_number(identities.at(0), identities.at(1));
    EXPECT_EQ(number.size(), safety_number_digits);
    EXPECT_TRUE(all_digits(number));
}

TEST(SafetyNumber, AnInviteFingerprintOfAnotherLengthNeverMatches)
{
    const auto identities = vector_identities();
    const auto expected = invite_fingerprint(identities.at(0));
    EXPECT_FALSE(matches_invite(identities.at(0), Bytes(expected.begin(), expected.end() - 1)));
    EXPECT_FALSE(matches_invite(identities.at(0), {}));
}

TEST(SafetyNumber, TheBindingIsNotPartOfTheIdentity)
{
    const auto subject = vector_identities().at(3);
    auto rebound = subject;
    rebound.binding.front() = static_cast<std::uint8_t>(rebound.binding.front() ^ 1U);
    EXPECT_TRUE(same_identity(subject, rebound));
    EXPECT_EQ(fingerprint(subject), fingerprint(rebound));
}

RC_GTEST_PROP(SafetyNumberProperties, BothSidesSeeTheSameNumber, ())
{
    const auto alice = random_identity();
    const auto bob = random_identity();
    RC_ASSERT(safety_number(alice, bob) == safety_number(bob, alice));
}

RC_GTEST_PROP(SafetyNumberProperties, EitherHalfOfTheIdentityChangesTheFingerprint, ())
{
    const auto subject = random_identity();
    auto other_signing = subject;
    const auto flipped_signing = test::flip_random_bit(subject.signing_key);
    std::ranges::copy(flipped_signing, other_signing.signing_key.begin());
    auto other_exchange = subject;
    const auto flipped_exchange = test::flip_random_bit(subject.exchange_key);
    std::ranges::copy(flipped_exchange, other_exchange.exchange_key.begin());

    const auto original = fingerprint(subject);
    RC_ASSERT(original != fingerprint(other_signing));
    RC_ASSERT(original != fingerprint(other_exchange));
    RC_ASSERT_FALSE(same_identity(subject, other_signing));
    RC_ASSERT_FALSE(same_identity(subject, other_exchange));
    RC_ASSERT_FALSE(matches_invite(other_signing, invite_fingerprint(subject)));
    RC_ASSERT_FALSE(matches_invite(other_exchange, invite_fingerprint(subject)));
}

RC_GTEST_PROP(IdentityMatchingProperties, OnlyTheSamePairIsTheSameIdentity, ())
{
    const auto subject = random_identity();
    const auto other = random_identity();
    RC_PRE(other.signing_key != subject.signing_key && other.exchange_key != subject.exchange_key);
    RC_ASSERT(same_identity(subject, subject));
    RC_ASSERT_FALSE(same_identity(subject, other));
    RC_ASSERT(matches_invite(subject, invite_fingerprint(subject)));
    RC_ASSERT_FALSE(matches_invite(subject, invite_fingerprint(other)));
}

}
}
