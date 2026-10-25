// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/aead.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

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
        const auto opened = aead_open(key, nonce, associated_data, ciphertext);

        if (vector.group.at("ivSize").get<std::size_t>() != aead_nonce_size * 8) {
            ASSERT_FALSE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(opened.error(), Error::invalid_size) << "tcId " << vector.id();
            EXPECT_FALSE(aead_seal(key, nonce, associated_data, plaintext).has_value()) << "tcId " << vector.id();
            return;
        }
        if (vector.result() == "valid") {
            const auto sealed = aead_seal(key, nonce, associated_data, plaintext);
            ASSERT_TRUE(sealed.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(*sealed, ciphertext) << "tcId " << vector.id();
            ASSERT_TRUE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(opened->equals(plaintext)) << "tcId " << vector.id();
        } else {
            ASSERT_FALSE(opened.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(opened.error(), Error::authentication_failed) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(XChaCha20Poly1305, CiphertextShorterThanTagIsRejected)
{
    const auto key = SecretBytes(aead_key_size);
    const Bytes nonce(aead_nonce_size);
    const auto opened = aead_open(key, nonce, {}, Bytes(aead_tag_size - 1));
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), Error::authentication_failed);
}

TEST(XChaCha20Poly1305, EmptyPlaintextRoundTrips)
{
    const auto key = SecretBytes(aead_key_size);
    const Bytes nonce(aead_nonce_size);
    const auto sealed = aead_seal(key, nonce, {}, {});
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->size(), aead_tag_size);
    const auto opened = aead_open(key, nonce, {}, *sealed);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->empty());
}

TEST(XChaCha20Poly1305, RejectsWrongKeySize)
{
    const Bytes nonce(aead_nonce_size);
    EXPECT_EQ(aead_seal(SecretBytes(16), nonce, {}, {}).error(), Error::invalid_size);
    EXPECT_EQ(aead_open(SecretBytes(16), nonce, {}, Bytes(aead_tag_size)).error(), Error::invalid_size);
}

struct Sealed {
    SecretBytes key;
    Bytes nonce;
    Bytes ciphertext;
};

Sealed seal_random(const Bytes& associated_data, const Bytes& plaintext)
{
    auto key = SecretBytes::copy_of(test::random_bytes_of(aead_key_size));
    auto nonce = test::random_bytes_of(aead_nonce_size);
    auto ciphertext = aead_seal(key, nonce, associated_data, plaintext);
    RC_ASSERT(ciphertext.has_value());
    return Sealed{std::move(key), std::move(nonce), std::move(*ciphertext)};
}

RC_GTEST_PROP(AeadProperties, OpenReversesSeal, (const Bytes& associated_data, const Bytes& plaintext))
{
    const auto sealed = seal_random(associated_data, plaintext);
    RC_ASSERT(sealed.ciphertext.size() == plaintext.size() + aead_tag_size);
    const auto opened = aead_open(sealed.key, sealed.nonce, associated_data, sealed.ciphertext);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(opened->equals(plaintext));
}

RC_GTEST_PROP(AeadProperties, AnyChangedCiphertextBitIsRejected, (const Bytes& associated_data, const Bytes& plaintext))
{
    const auto sealed = seal_random(associated_data, plaintext);
    const auto forged = test::flip_random_bit(sealed.ciphertext);
    RC_ASSERT_FALSE(aead_open(sealed.key, sealed.nonce, associated_data, forged).has_value());
}

RC_GTEST_PROP(AeadProperties, AnyChangedAssociatedDataBitIsRejected,
    (const Bytes& associated_data, const Bytes& plaintext))
{
    RC_PRE(!associated_data.empty());
    const auto sealed = seal_random(associated_data, plaintext);
    const auto other = test::flip_random_bit(associated_data);
    RC_ASSERT_FALSE(aead_open(sealed.key, sealed.nonce, other, sealed.ciphertext).has_value());
}

RC_GTEST_PROP(AeadProperties, AnyChangedNonceBitIsRejected, (const Bytes& plaintext))
{
    const auto sealed = seal_random({}, plaintext);
    const auto other = test::flip_random_bit(sealed.nonce);
    RC_ASSERT_FALSE(aead_open(sealed.key, other, {}, sealed.ciphertext).has_value());
}

RC_GTEST_PROP(AeadProperties, AnotherKeyIsRejected, (const Bytes& plaintext))
{
    const auto sealed = seal_random({}, plaintext);
    const auto other_key = SecretBytes::copy_of(test::flip_random_bit(sealed.key.view()));
    RC_ASSERT_FALSE(aead_open(other_key, sealed.nonce, {}, sealed.ciphertext).has_value());
}

}
}
