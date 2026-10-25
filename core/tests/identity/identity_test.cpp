// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/identity/identity.hpp"

#include "lume/identity/phrase.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::identity {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

Identity identity_from(const Bytes& entropy)
{
    auto identity = derive_identity(SecretBytes::copy_of(entropy));
    if (!identity) {
        throw std::runtime_error("deriving an identity from 32 bytes failed");
    }
    return std::move(*identity);
}

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

TEST(Identity, MatchesTheLumeVectors)
{
    const auto cases = test::load_vectors("lume/identity.json").at("cases");
    ASSERT_EQ(cases.size(), 8U);
    int certificates = 0;
    for (const auto& vector : cases) {
        const auto phrase = vector.at("phrase").get<std::string>();
        const auto entropy = entropy_from_phrase(Bytes(phrase.begin(), phrase.end()));
        ASSERT_TRUE(entropy.has_value());
        ASSERT_TRUE(entropy->equals(hex_field(vector, "entropy")));

        const auto identity = derive_identity(*entropy);
        ASSERT_TRUE(identity.has_value());
        EXPECT_TRUE(identity->signing.seed.equals(hex_field(vector, "signing_seed")));
        EXPECT_EQ(test::to_hex(identity->signing.public_key), vector.at("signing_key").get<std::string>());
        EXPECT_TRUE(identity->exchange.secret_key.equals(hex_field(vector, "exchange_secret")));
        EXPECT_EQ(test::to_hex(identity->exchange.public_key), vector.at("exchange_key").get<std::string>());
        EXPECT_EQ(test::to_hex(identity->binding), vector.at("binding").get<std::string>());
        EXPECT_TRUE(verify_binding(public_identity(*identity)));

        const auto device_key = hex_field(vector, "device_key");
        const auto device = crypto::ed25519_from_seed(SecretBytes::copy_of(hex_field(vector, "device_seed")));
        ASSERT_TRUE(device.has_value());
        EXPECT_EQ(Bytes(device->public_key.begin(), device->public_key.end()), device_key);
        for (const auto& expected : vector.at("certificates")) {
            const auto generation = expected.at("generation").get<std::uint32_t>();
            const auto certificate = certify_device(*identity, device_key, generation);
            ASSERT_TRUE(certificate.has_value());
            EXPECT_EQ(test::to_hex(*certificate), expected.at("certificate").get<std::string>());
            EXPECT_TRUE(verify_device_certificate(identity->signing.public_key, device_key, generation, *certificate));
            ++certificates;
        }
    }
    EXPECT_EQ(certificates, 24);
}

TEST(Identity, RejectsEntropyOfTheWrongSize)
{
    EXPECT_EQ(derive_identity(SecretBytes(entropy_size - 1)).error(), crypto::Error::invalid_size);
    EXPECT_EQ(derive_identity(SecretBytes(entropy_size + 1)).error(), crypto::Error::invalid_size);
}

TEST(Identity, PublicIdentityCopiesTheKeysAndBinding)
{
    const auto identity = identity_from(Bytes(entropy_size, 9));
    const auto published = public_identity(identity);
    EXPECT_EQ(published.signing_key, identity.signing.public_key);
    EXPECT_EQ(published.exchange_key, identity.exchange.public_key);
    EXPECT_EQ(published.binding, identity.binding);
}

TEST(DeviceCertificate, RefusesGenerationZeroAndWrongSizes)
{
    const auto identity = identity_from(Bytes(entropy_size, 1));
    const auto device = crypto::ed25519_generate();
    EXPECT_EQ(certify_device(identity, device.public_key, 0).error(), crypto::Error::out_of_range);
    EXPECT_EQ(certify_device(identity, Bytes(31), first_generation).error(), crypto::Error::invalid_size);

    const auto certificate = certify_device(identity, device.public_key, first_generation);
    ASSERT_TRUE(certificate.has_value());
    EXPECT_FALSE(verify_device_certificate(identity.signing.public_key, device.public_key, 0, *certificate));
    EXPECT_FALSE(verify_device_certificate(identity.signing.public_key, Bytes(31), first_generation, *certificate));
    EXPECT_FALSE(verify_device_certificate(Bytes(31), device.public_key, first_generation, *certificate));
    EXPECT_FALSE(verify_device_certificate(
        identity.signing.public_key, device.public_key, first_generation, Bytes(certificate->begin(), certificate->end() - 1)));
}

TEST(DeviceCertificate, CoversTheLargestGeneration)
{
    const auto identity = identity_from(Bytes(entropy_size, 2));
    const auto device = crypto::ed25519_generate();
    constexpr auto largest = std::numeric_limits<std::uint32_t>::max();
    const auto certificate = certify_device(identity, device.public_key, largest);
    ASSERT_TRUE(certificate.has_value());
    EXPECT_TRUE(verify_device_certificate(identity.signing.public_key, device.public_key, largest, *certificate));
    EXPECT_FALSE(verify_device_certificate(identity.signing.public_key, device.public_key, largest - 1, *certificate));
}

Identity random_identity()
{
    return identity_from(test::random_bytes_of(entropy_size));
}

RC_GTEST_PROP(IdentityProperties, DerivationIsDeterministic, ())
{
    const auto entropy = test::random_bytes_of(entropy_size);
    const auto first = public_identity(identity_from(entropy));
    const auto second = public_identity(identity_from(entropy));
    RC_ASSERT(first.signing_key == second.signing_key);
    RC_ASSERT(first.exchange_key == second.exchange_key);
    RC_ASSERT(first.binding == second.binding);
}

RC_GTEST_PROP(IdentityProperties, DifferentEntropyGivesUnrelatedKeys, ())
{
    const auto entropy = test::random_bytes_of(entropy_size);
    const auto first = public_identity(identity_from(entropy));
    const auto second = public_identity(identity_from(test::flip_random_bit(entropy)));
    RC_ASSERT(first.signing_key != second.signing_key);
    RC_ASSERT(first.exchange_key != second.exchange_key);
}

RC_GTEST_PROP(IdentityProperties, TheBindingCoversBothHalves, ())
{
    const auto published = public_identity(random_identity());
    RC_ASSERT(verify_binding(published));

    const auto other = public_identity(random_identity());
    RC_PRE(other.signing_key != published.signing_key && other.exchange_key != published.exchange_key);
    auto swapped_exchange = published;
    swapped_exchange.exchange_key = other.exchange_key;
    RC_ASSERT_FALSE(verify_binding(swapped_exchange));

    auto swapped_signing = published;
    swapped_signing.signing_key = other.signing_key;
    RC_ASSERT_FALSE(verify_binding(swapped_signing));

    auto borrowed_binding = published;
    borrowed_binding.binding = other.binding;
    RC_ASSERT_FALSE(verify_binding(borrowed_binding));
}

RC_GTEST_PROP(IdentityProperties, AnyChangedBindingBitIsRejected, ())
{
    auto published = public_identity(random_identity());
    const auto forged = test::flip_random_bit(published.binding);
    std::ranges::copy(forged, published.binding.begin());
    RC_ASSERT_FALSE(verify_binding(published));
}

RC_GTEST_PROP(IdentityProperties, ACertificateNamesOneDeviceOneGenerationOneIdentity, ())
{
    const auto identity = random_identity();
    const auto device = crypto::ed25519_from_seed(SecretBytes::copy_of(test::random_bytes_of(crypto::ed25519_seed_size)));
    RC_ASSERT(device.has_value());
    const auto generation = *rc::gen::inRange<std::uint32_t>(first_generation, std::numeric_limits<std::uint32_t>::max());
    const auto certificate = certify_device(identity, device->public_key, generation);
    RC_ASSERT(certificate.has_value());
    const auto& signer = identity.signing.public_key;
    RC_ASSERT(verify_device_certificate(signer, device->public_key, generation, *certificate));
    RC_ASSERT_FALSE(verify_device_certificate(signer, device->public_key, generation + 1, *certificate));
    RC_ASSERT_FALSE(verify_device_certificate(signer, test::flip_random_bit(device->public_key), generation, *certificate));
    const auto other = random_identity();
    RC_PRE(other.signing.public_key != signer);
    RC_ASSERT_FALSE(verify_device_certificate(other.signing.public_key, device->public_key, generation, *certificate));
    RC_ASSERT_FALSE(verify_device_certificate(signer, device->public_key, generation, test::flip_random_bit(*certificate)));
}

RC_GTEST_PROP(IdentityProperties, ACertificateIsNotABinding, ())
{
    const auto identity = random_identity();
    auto published = public_identity(identity);
    const auto certificate = certify_device(identity, published.exchange_key, first_generation);
    RC_ASSERT(certificate.has_value());
    published.binding = *certificate;
    RC_ASSERT_FALSE(verify_binding(published));
}

}
}
