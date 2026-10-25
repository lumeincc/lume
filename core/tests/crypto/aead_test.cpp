// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/aead.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/random.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace lume::crypto {
namespace {

Bytes concatenated(const Bytes& first, const Bytes& second)
{
    Bytes joined(first);
    joined.insert(joined.end(), second.begin(), second.end());
    return joined;
}

TEST(XChaCha20Poly1305, MatchesWycheproof)
{
    const auto suite = test::load_wycheproof("xchacha20_poly1305_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto key = SecretBytes::copy_of(vector.bytes("key"));
        const auto nonce = vector.bytes("iv");
        const auto associated_data = vector.bytes("aad");
        const auto plaintext = vector.bytes("msg");
        const auto ciphertext = concatenated(vector.bytes("ct"), vector.bytes("tag"));
        const auto opened = detail::aead_decrypt(key, nonce, associated_data, ciphertext);

        if (vector.group.at("ivSize").get<std::size_t>() != aead_nonce_size * 8) {
            ASSERT_FALSE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(opened.error(), Error::invalid_size) << "tcId " << vector.id();
            const auto sealed = detail::aead_encrypt(key, nonce, associated_data, plaintext);
            ASSERT_FALSE(sealed.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(sealed.error(), Error::invalid_size) << "tcId " << vector.id();
            return;
        }
        if (vector.result() == "valid") {
            const auto sealed = detail::aead_encrypt(key, nonce, associated_data, plaintext);
            ASSERT_TRUE(sealed.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(*sealed, ciphertext) << "tcId " << vector.id();
            ASSERT_TRUE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(opened->equals(plaintext)) << "tcId " << vector.id();
            const auto reopened = aead_open(key, associated_data, concatenated(nonce, ciphertext));
            ASSERT_TRUE(reopened.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(reopened->equals(plaintext)) << "tcId " << vector.id();
        } else {
            ASSERT_FALSE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(opened.error(), Error::authentication_failed) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(XChaCha20Poly1305, InputShorterThanTheOverheadIsRejected)
{
    const auto key = SecretBytes(aead_key_size);
    const auto opened = aead_open(key, {}, Bytes(aead_overhead - 1));
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), Error::authentication_failed);
    const auto decrypted = detail::aead_decrypt(key, Bytes(aead_nonce_size), {}, Bytes(aead_tag_size - 1));
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), Error::authentication_failed);
}

TEST(XChaCha20Poly1305, EmptyPlaintextRoundTrips)
{
    const auto key = SecretBytes(aead_key_size);
    const auto sealed = aead_seal(key, {}, {});
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->size(), aead_overhead);
    const auto opened = aead_open(key, {}, *sealed);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->empty());
}

TEST(XChaCha20Poly1305, RejectsWrongKeySize)
{
    EXPECT_EQ(aead_seal(SecretBytes(16), {}, {}).error(), Error::invalid_size);
    EXPECT_EQ(aead_open(SecretBytes(16), {}, Bytes(aead_overhead)).error(), Error::invalid_size);
}

TEST(XChaCha20Poly1305, LargestPlaintextRoundTrips)
{
    const auto key = random_secret(aead_key_size);
    const Bytes plaintext(aead_max_plaintext_size, 0x5a);
    const auto sealed = aead_seal(key, {}, plaintext);
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->size(), aead_max_plaintext_size + aead_overhead);
    const auto opened = aead_open(key, {}, *sealed);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->equals(plaintext));
}

TEST(XChaCha20Poly1305, RefusesMoreThanTheLargestPlaintextBeforeTouchingIt)
{
    const auto key = random_secret(aead_key_size);
    EXPECT_EQ(aead_seal(key, {}, Bytes(aead_max_plaintext_size + 1)).error(), Error::invalid_size);
    EXPECT_EQ(aead_open(key, {}, Bytes(aead_max_plaintext_size + aead_overhead + 1)).error(), Error::invalid_size);
}

TEST(XChaCha20Poly1305, EverySealUsesAFreshNonce)
{
    const auto key = random_secret(aead_key_size);
    const Bytes plaintext{1, 2, 3};
    const auto first = aead_seal(key, {}, plaintext);
    const auto second = aead_seal(key, {}, plaintext);
    ASSERT_TRUE(first.has_value() && second.has_value());
    EXPECT_FALSE(std::ranges::equal(ByteView(*first).first(aead_nonce_size), ByteView(*second).first(aead_nonce_size)));
    EXPECT_NE(*first, *second);
}

struct Sealed {
    SecretBytes key;
    Bytes sealed;
};

Sealed seal_random(const Bytes& associated_data, const Bytes& plaintext)
{
    auto key = SecretBytes::copy_of(test::random_bytes_of(aead_key_size));
    auto sealed = aead_seal(key, associated_data, plaintext);
    RC_ASSERT(sealed.has_value());
    return Sealed{.key = std::move(key), .sealed = std::move(*sealed)};
}

RC_GTEST_PROP(AeadProperties, OpenReversesSeal, (const Bytes& associated_data, const Bytes& plaintext))
{
    const auto sealed = seal_random(associated_data, plaintext);
    RC_ASSERT(sealed.sealed.size() == plaintext.size() + aead_overhead);
    const auto opened = aead_open(sealed.key, associated_data, sealed.sealed);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(opened->equals(plaintext));
}

RC_GTEST_PROP(AeadProperties, AnyChangedBitIsRejected, (const Bytes& associated_data, const Bytes& plaintext))
{
    const auto sealed = seal_random(associated_data, plaintext);
    const auto forged = test::flip_random_bit(sealed.sealed);
    RC_ASSERT_FALSE(aead_open(sealed.key, associated_data, forged).has_value());
}

RC_GTEST_PROP(AeadProperties, AnyChangedNonceBitIsRejected, (const Bytes& plaintext))
{
    const auto sealed = seal_random({}, plaintext);
    const auto index = *rc::gen::inRange<std::size_t>(0, aead_nonce_size);
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    RC_ASSERT_FALSE(aead_open(sealed.key, {}, test::flip_bit(sealed.sealed, index, bit)).has_value());
}

RC_GTEST_PROP(AeadProperties, AnyChangedAssociatedDataBitIsRejected,
    (const Bytes& associated_data, const Bytes& plaintext))
{
    RC_PRE(!associated_data.empty());
    const auto sealed = seal_random(associated_data, plaintext);
    const auto other = test::flip_random_bit(associated_data);
    RC_ASSERT_FALSE(aead_open(sealed.key, other, sealed.sealed).has_value());
}

RC_GTEST_PROP(AeadProperties, AnotherKeyIsRejected, (const Bytes& plaintext))
{
    const auto sealed = seal_random({}, plaintext);
    const auto other_key = SecretBytes::copy_of(test::flip_random_bit(sealed.key.view()));
    RC_ASSERT_FALSE(aead_open(other_key, {}, sealed.sealed).has_value());
}

}
}
