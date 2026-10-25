// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/mlkem.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <algorithm>

namespace lume::crypto {
namespace {

TEST(MlKem768, KeyGenerationFromSeedMatchesWycheproof)
{
    const auto suite = test::load_wycheproof("mlkem_768_keygen_seed_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(vector.bytes("seed")));
        ASSERT_TRUE(key_pair.has_value()) << "tcId " << vector.id();
        EXPECT_EQ(key_pair->public_key, vector.bytes("ek")) << "tcId " << vector.id();
        EXPECT_TRUE(key_pair->secret_key.equals(vector.bytes("dk"))) << "tcId " << vector.id();
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(MlKem768, EncapsulationMatchesWycheproofAndChecksTheKey)
{
    const auto suite = test::load_wycheproof("mlkem_768_encaps_test.json");
    int rejected = 0;
    const int checked = test::for_each_wycheproof_case(suite, [&rejected](const test::WycheproofCase& vector) {
        const auto encapsulation =
            mlkem768_encapsulate_deterministic(vector.bytes("ek"), SecretBytes::copy_of(vector.bytes("m")));
        if (vector.result() == "valid") {
            ASSERT_TRUE(encapsulation.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(encapsulation->ciphertext, vector.bytes("c")) << "tcId " << vector.id();
            EXPECT_TRUE(encapsulation->shared_secret.equals(vector.bytes("K"))) << "tcId " << vector.id();
        } else {
            EXPECT_FALSE(encapsulation.has_value()) << "tcId " << vector.id();
            ++rejected;
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
    EXPECT_GT(rejected, 0);
}

TEST(MlKem768, DecapsulationMatchesWycheproof)
{
    const auto suite = test::load_wycheproof("mlkem_768_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(vector.bytes("seed")));
        if (!key_pair) {
            EXPECT_EQ(vector.result(), "invalid") << "tcId " << vector.id();
            EXPECT_EQ(key_pair.error(), Error::invalid_size) << "tcId " << vector.id();
            return;
        }
        if (vector.test.contains("ek")) {
            EXPECT_EQ(key_pair->public_key, vector.bytes("ek")) << "tcId " << vector.id();
        }
        const auto shared = mlkem768_decapsulate(key_pair->secret_key, vector.bytes("c"));
        if (vector.result() == "valid") {
            ASSERT_TRUE(shared.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(shared->equals(vector.bytes("K"))) << "tcId " << vector.id();
        } else {
            ASSERT_FALSE(shared.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(shared.error(), Error::invalid_size) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(MlKem768, RejectsWrongSizes)
{
    EXPECT_EQ(mlkem768_from_seed(SecretBytes(63)).error(), Error::invalid_size);
    EXPECT_EQ(mlkem768_encapsulate(Bytes(mlkem768_public_key_size - 1)).error(), Error::invalid_size);
    EXPECT_EQ(
        mlkem768_encapsulate_deterministic(Bytes(mlkem768_public_key_size), SecretBytes(31)).error(),
        Error::invalid_size);
    EXPECT_EQ(
        mlkem768_decapsulate(SecretBytes(mlkem768_secret_key_size), Bytes(mlkem768_ciphertext_size + 1)).error(),
        Error::invalid_size);
}

TEST(MlKem768, GeneratedKeyPairsDiffer)
{
    const auto first = mlkem768_generate();
    const auto second = mlkem768_generate();
    ASSERT_TRUE(first.has_value() && second.has_value());
    EXPECT_NE(first->public_key, second->public_key);
}

RC_GTEST_PROP(MlKemProperties, DecapsulationRecoversTheSharedSecret, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_key_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto shared = mlkem768_decapsulate(key_pair->secret_key, encapsulation->ciphertext);
    RC_ASSERT(shared.has_value());
    RC_ASSERT(shared->equals(encapsulation->shared_secret.view()));
}

RC_GTEST_PROP(MlKemProperties, ChangedCiphertextGivesAnUnrelatedSecret, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_key_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto forged = test::flip_random_bit(encapsulation->ciphertext);
    const auto shared = mlkem768_decapsulate(key_pair->secret_key, forged);
    RC_ASSERT(shared.has_value());
    RC_ASSERT_FALSE(shared->equals(encapsulation->shared_secret.view()));
}

RC_GTEST_PROP(MlKemProperties, DeterministicEncapsulationIsReproducible, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_key_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto seed = SecretBytes::copy_of(test::random_bytes_of(mlkem768_encapsulation_seed_size));
    const auto first = mlkem768_encapsulate_deterministic(key_pair->public_key, seed);
    const auto second = mlkem768_encapsulate_deterministic(key_pair->public_key, seed);
    RC_ASSERT(first.has_value() && second.has_value());
    RC_ASSERT(first->ciphertext == second->ciphertext);
    RC_ASSERT(first->shared_secret.equals(second->shared_secret.view()));
}

}
}
