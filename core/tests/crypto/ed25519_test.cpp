// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/ed25519.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <stdexcept>
#include <utility>

namespace lume::crypto {
namespace {

Ed25519KeyPair key_pair_from(const Bytes& seed)
{
    auto key_pair = ed25519_from_seed(SecretBytes::copy_of(seed));
    if (!key_pair) {
        throw std::runtime_error("Ed25519 key pair from a 32-byte seed failed");
    }
    return std::move(*key_pair);
}

TEST(Ed25519, VerifiesExactlyLikeWycheproof)
{
    const auto suite = test::load_wycheproof("ed25519_test.json");
    int acceptable = 0;
    const int checked = test::for_each_wycheproof_case(suite, [&acceptable](const test::WycheproofCase& vector) {
        const auto public_key = test::from_hex(vector.group.at("publicKey").at("pk").get<std::string>());
        const bool verified = ed25519_verify(public_key, vector.bytes("msg"), vector.bytes("sig"));
        if (vector.result() == "acceptable") {
            ++acceptable;
            return;
        }
        EXPECT_EQ(verified, vector.result() == "valid") << "tcId " << vector.id();
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
    EXPECT_LT(acceptable, checked);
}

TEST(Ed25519, Rfc8032FirstVectorFromSeed)
{
    const auto key_pair =
        key_pair_from(test::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    EXPECT_EQ(test::to_hex(key_pair.public_key), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto signature = ed25519_sign(key_pair.secret_key, {});
    ASSERT_TRUE(signature.has_value());
    EXPECT_EQ(
        test::to_hex(*signature),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
}

TEST(Ed25519, RejectsWrongSizes)
{
    EXPECT_EQ(ed25519_from_seed(SecretBytes(31)).error(), Error::invalid_size);
    EXPECT_EQ(ed25519_sign(SecretBytes(32), {}).error(), Error::invalid_size);
    const auto key_pair = ed25519_generate();
    const auto signature = ed25519_sign(key_pair.secret_key, {});
    ASSERT_TRUE(signature.has_value());
    EXPECT_FALSE(ed25519_verify(ByteView(key_pair.public_key).first(31), {}, *signature));
    EXPECT_FALSE(ed25519_verify(key_pair.public_key, {}, ByteView(*signature).first(63)));
}

RC_GTEST_PROP(Ed25519Properties, SignatureVerifies, (const Bytes& message))
{
    const auto key_pair = key_pair_from(test::random_bytes_of(ed25519_seed_size));
    const auto signature = ed25519_sign(key_pair.secret_key, message);
    RC_ASSERT(signature.has_value());
    RC_ASSERT(ed25519_verify(key_pair.public_key, message, *signature));
}

RC_GTEST_PROP(Ed25519Properties, SigningIsDeterministic, (const Bytes& message))
{
    const auto seed = test::random_bytes_of(ed25519_seed_size);
    const auto first = ed25519_sign(key_pair_from(seed).secret_key, message);
    const auto second = ed25519_sign(key_pair_from(seed).secret_key, message);
    RC_ASSERT(first.has_value() && second.has_value());
    RC_ASSERT(*first == *second);
}

RC_GTEST_PROP(Ed25519Properties, AnyChangedSignatureBitIsRejected, (const Bytes& message))
{
    const auto key_pair = key_pair_from(test::random_bytes_of(ed25519_seed_size));
    const auto signature = ed25519_sign(key_pair.secret_key, message);
    RC_ASSERT(signature.has_value());
    RC_ASSERT_FALSE(ed25519_verify(key_pair.public_key, message, test::flip_random_bit(*signature)));
}

RC_GTEST_PROP(Ed25519Properties, AnyChangedMessageBitIsRejected, (const Bytes& message))
{
    RC_PRE(!message.empty());
    const auto key_pair = key_pair_from(test::random_bytes_of(ed25519_seed_size));
    const auto signature = ed25519_sign(key_pair.secret_key, message);
    RC_ASSERT(signature.has_value());
    RC_ASSERT_FALSE(ed25519_verify(key_pair.public_key, test::flip_random_bit(message), *signature));
}

RC_GTEST_PROP(Ed25519Properties, AnotherKeyDoesNotVerify, (const Bytes& message))
{
    const auto signer = key_pair_from(test::random_bytes_of(ed25519_seed_size));
    const auto other = key_pair_from(test::random_bytes_of(ed25519_seed_size));
    RC_PRE(signer.public_key != other.public_key);
    const auto signature = ed25519_sign(signer.secret_key, message);
    RC_ASSERT(signature.has_value());
    RC_ASSERT_FALSE(ed25519_verify(other.public_key, message, *signature));
}

}
}
