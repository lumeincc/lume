// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/x25519.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace lume::crypto {
namespace {

bool all_zero(ByteView bytes)
{
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

X25519KeyPair key_pair_from(const Bytes& seed)
{
    auto key_pair = x25519_from_secret(SecretBytes::copy_of(seed));
    if (!key_pair) {
        throw std::runtime_error("X25519 key pair from a 32-byte secret failed");
    }
    return std::move(*key_pair);
}

TEST(X25519, MatchesWycheproof)
{
    const auto suite = test::load_wycheproof("x25519_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto secret_key = SecretBytes::copy_of(vector.bytes("private"));
        const auto expected = vector.bytes("shared");
        const auto shared = x25519_shared_secret(secret_key, vector.bytes("public"));
        if (all_zero(expected)) {
            ASSERT_FALSE(shared.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(shared.error(), Error::weak_public_key) << "tcId " << vector.id();
        } else {
            ASSERT_TRUE(shared.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(shared->equals(expected)) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(X25519, GeneratedKeyPairIsConsistent)
{
    const auto generated = x25519_generate();
    const auto rebuilt = x25519_from_secret(generated.secret_key.clone());
    ASSERT_TRUE(rebuilt.has_value());
    EXPECT_EQ(rebuilt->public_key, generated.public_key);
}

TEST(X25519, RejectsWrongSizes)
{
    const auto generated = x25519_generate();
    EXPECT_EQ(x25519_from_secret(SecretBytes(31)).error(), Error::invalid_size);
    EXPECT_EQ(x25519_shared_secret(generated.secret_key, Bytes(31)).error(), Error::invalid_size);
    EXPECT_EQ(x25519_shared_secret(SecretBytes(33), generated.public_key).error(), Error::invalid_size);
}

RC_GTEST_PROP(X25519Properties, BothSidesDeriveTheSameSecret, ())
{
    const auto alice = key_pair_from(test::random_bytes_of(x25519_key_size));
    const auto bob = key_pair_from(test::random_bytes_of(x25519_key_size));
    const auto alice_view = x25519_shared_secret(alice.secret_key, bob.public_key);
    const auto bob_view = x25519_shared_secret(bob.secret_key, alice.public_key);
    RC_ASSERT(alice_view.has_value() && bob_view.has_value());
    RC_ASSERT(alice_view->equals(bob_view->view()));
}

RC_GTEST_PROP(X25519Properties, DifferentPeersGiveDifferentSecrets, ())
{
    const auto alice = key_pair_from(test::random_bytes_of(x25519_key_size));
    const auto bob = key_pair_from(test::random_bytes_of(x25519_key_size));
    const auto carol = key_pair_from(test::random_bytes_of(x25519_key_size));
    RC_PRE(bob.public_key != carol.public_key);
    const auto with_bob = x25519_shared_secret(alice.secret_key, bob.public_key);
    const auto with_carol = x25519_shared_secret(alice.secret_key, carol.public_key);
    RC_ASSERT(with_bob.has_value() && with_carol.has_value());
    RC_ASSERT_FALSE(with_bob->equals(with_carol->view()));
}

}
}
