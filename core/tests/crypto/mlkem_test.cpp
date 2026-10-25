// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/mlkem.hpp"

#include "crypto/mlkem_internal.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>

namespace lume::crypto {
namespace {

using detail::mlkem768_encapsulate_deterministic;
using detail::mlkem768_encapsulation_randomness_size;

TEST(MlKem768, KeyGenerationFromSeedMatchesWycheproof)
{
    const auto suite = test::load_wycheproof("mlkem_768_keygen_seed_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(vector.bytes("seed")));
        ASSERT_TRUE(key_pair.has_value()) << "tcId " << vector.id();
        EXPECT_EQ(key_pair->public_key, vector.bytes("ek")) << "tcId " << vector.id();
        EXPECT_TRUE(key_pair->seed.equals(vector.bytes("seed"))) << "tcId " << vector.id();
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(MlKem768, EncapsulationMatchesWycheproofAndChecksTheKey)
{
    const auto suite = test::load_wycheproof("mlkem_768_encaps_test.json");
    int invalid = 0;
    int rejected = 0;
    const int checked = test::for_each_wycheproof_case(suite, [&](const test::WycheproofCase& vector) {
        const auto public_key = vector.bytes("ek");
        const auto encapsulation =
            mlkem768_encapsulate_deterministic(public_key, SecretBytes::copy_of(vector.bytes("m")));
        if (vector.result() == "valid") {
            ASSERT_TRUE(encapsulation.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(encapsulation->ciphertext, vector.bytes("c")) << "tcId " << vector.id();
            EXPECT_TRUE(encapsulation->shared_secret.equals(vector.bytes("K"))) << "tcId " << vector.id();
            return;
        }
        ++invalid;
        ASSERT_FALSE(encapsulation.has_value()) << "tcId " << vector.id();
        ++rejected;
        const auto expected =
            public_key.size() == mlkem768_public_key_size ? Error::invalid_key : Error::invalid_size;
        EXPECT_EQ(encapsulation.error(), expected) << "tcId " << vector.id();
        if (public_key.size() == mlkem768_public_key_size) {
            const auto random_encapsulation = mlkem768_encapsulate(public_key);
            ASSERT_FALSE(random_encapsulation.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(random_encapsulation.error(), Error::invalid_key) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
    EXPECT_GT(invalid, 100);
    EXPECT_EQ(rejected, invalid);
}

TEST(MlKem768, DecapsulationMatchesWycheproof)
{
    const auto suite = test::load_wycheproof("mlkem_768_test.json");
    int invalid = 0;
    int rejected = 0;
    const int checked = test::for_each_wycheproof_case(suite, [&](const test::WycheproofCase& vector) {
        const auto seed = SecretBytes::copy_of(vector.bytes("seed"));
        const auto shared = mlkem768_decapsulate(seed, vector.bytes("c"));
        if (vector.result() == "valid") {
            ASSERT_TRUE(shared.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(shared->equals(vector.bytes("K"))) << "tcId " << vector.id();
            if (vector.test.contains("ek")) {
                const auto key_pair = mlkem768_from_seed(seed.clone());
                ASSERT_TRUE(key_pair.has_value()) << "tcId " << vector.id();
                EXPECT_EQ(key_pair->public_key, vector.bytes("ek")) << "tcId " << vector.id();
            }
            return;
        }
        ++invalid;
        ASSERT_FALSE(shared.has_value()) << "tcId " << vector.id();
        ++rejected;
        EXPECT_EQ(shared.error(), Error::invalid_size) << "tcId " << vector.id();
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
    EXPECT_GT(invalid, 0);
    EXPECT_EQ(rejected, invalid);
}

TEST(MlKem768, RejectsWrongSizes)
{
    EXPECT_EQ(mlkem768_from_seed(SecretBytes(mlkem768_seed_size - 1)).error(), Error::invalid_size);
    EXPECT_EQ(mlkem768_from_seed(SecretBytes(2400)).error(), Error::invalid_size);
    EXPECT_EQ(mlkem768_encapsulate(Bytes(mlkem768_public_key_size - 1)).error(), Error::invalid_size);
    EXPECT_EQ(
        mlkem768_encapsulate_deterministic(
            Bytes(mlkem768_public_key_size), SecretBytes(mlkem768_encapsulation_randomness_size - 1))
            .error(),
        Error::invalid_size);
    EXPECT_EQ(
        mlkem768_decapsulate(SecretBytes(mlkem768_seed_size), Bytes(mlkem768_ciphertext_size + 1)).error(),
        Error::invalid_size);
    EXPECT_EQ(
        mlkem768_decapsulate(SecretBytes(2400), Bytes(mlkem768_ciphertext_size)).error(), Error::invalid_size);
}

TEST(MlKem768, GeneratedKeyPairsDiffer)
{
    const auto first = mlkem768_generate();
    const auto second = mlkem768_generate();
    EXPECT_NE(first.public_key, second.public_key);
    EXPECT_FALSE(first.seed.equals(second.seed.view()));
}

RC_GTEST_PROP(MlKemProperties, DecapsulationRecoversTheSharedSecret, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto shared = mlkem768_decapsulate(key_pair->seed, encapsulation->ciphertext);
    RC_ASSERT(shared.has_value());
    RC_ASSERT(shared->equals(encapsulation->shared_secret.view()));
}

RC_GTEST_PROP(MlKemProperties, ChangedCiphertextGivesAnUnrelatedSecret, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto forged = test::flip_random_bit(encapsulation->ciphertext);
    const auto shared = mlkem768_decapsulate(key_pair->seed, forged);
    RC_ASSERT(shared.has_value());
    RC_ASSERT_FALSE(shared->equals(encapsulation->shared_secret.view()));
}

RC_GTEST_PROP(MlKemProperties, AnotherKeySeedCannotDecapsulate, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto index = *rc::gen::inRange<std::size_t>(0, mlkem768_seed_size / 2);
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    const auto other_seed = SecretBytes::copy_of(test::flip_bit(key_pair->seed.view(), index, bit));
    const auto shared = mlkem768_decapsulate(other_seed, encapsulation->ciphertext);
    RC_ASSERT(shared.has_value());
    RC_ASSERT_FALSE(shared->equals(encapsulation->shared_secret.view()));
}

RC_GTEST_PROP(MlKemProperties, TheRejectionHalfOfTheSeedChangesOnlyTheRejectionSecret, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    RC_ASSERT(encapsulation.has_value());
    const auto index = *rc::gen::inRange<std::size_t>(mlkem768_seed_size / 2, mlkem768_seed_size);
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    const auto other_seed = SecretBytes::copy_of(test::flip_bit(key_pair->seed.view(), index, bit));
    const auto shared = mlkem768_decapsulate(other_seed, encapsulation->ciphertext);
    RC_ASSERT(shared.has_value());
    RC_ASSERT(shared->equals(encapsulation->shared_secret.view()));
    const auto forged = test::flip_random_bit(encapsulation->ciphertext);
    const auto rejected = mlkem768_decapsulate(key_pair->seed, forged);
    const auto rejected_by_other = mlkem768_decapsulate(other_seed, forged);
    RC_ASSERT(rejected.has_value() && rejected_by_other.has_value());
    RC_ASSERT_FALSE(rejected->equals(rejected_by_other->view()));
}

RC_GTEST_PROP(MlKemProperties, DeterministicEncapsulationIsReproducible, ())
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(test::random_bytes_of(mlkem768_seed_size)));
    RC_ASSERT(key_pair.has_value());
    const auto randomness = SecretBytes::copy_of(test::random_bytes_of(mlkem768_encapsulation_randomness_size));
    const auto first = mlkem768_encapsulate_deterministic(key_pair->public_key, randomness);
    const auto second = mlkem768_encapsulate_deterministic(key_pair->public_key, randomness);
    RC_ASSERT(first.has_value() && second.has_value());
    RC_ASSERT(first->ciphertext == second->ciphertext);
    RC_ASSERT(first->shared_secret.equals(second->shared_secret.view()));
}

}
}
