// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/seal.hpp"

#include "lume/crypto/aead.hpp"
#include "lume/crypto/random.hpp"
#include "lume/ratchet/ratchet.hpp"
#include "lume/seal/padding.hpp"
#include "seal/seal_internal.hpp"
#include "support/mutate.hpp"
#include "support/random_stream.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::seal {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

template <typename T, typename E>
T must(std::expected<T, E> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

struct Recipient {
    wire::PrekeyX published;
    crypto::X25519KeyPair keys;
};

wire::PrekeyX published_seal_key(std::uint32_t id, const crypto::ByteArray<crypto::x25519_key_size>& public_key)
{
    return wire::PrekeyX{
        .kind = wire::PrekeyKind::seal_key,
        .id = id,
        .key = public_key,
        .signature = crypto::ByteArray<wire::signature_size>{}};
}

Recipient new_recipient(std::uint32_t id)
{
    auto keys = crypto::x25519_generate();
    auto published = published_seal_key(id, keys.public_key);
    return Recipient{.published = published, .keys = std::move(keys)};
}

wire::Inner inner_with(std::size_t body_size, bool with_initial)
{
    wire::Inner inner;
    inner.sender = crypto::random_public_bytes<wire::ed25519_key_size>();
    if (with_initial) {
        wire::InitialHeader initial;
        initial.ik_sig = inner.sender;
        initial.ephemeral_key = crypto::random_public_bytes<wire::x25519_key_size>();
        initial.opk_id = 1;
        inner.initial = initial;
    }
    inner.message.encrypted_header = crypto::random_public_bytes<wire::encrypted_header_size>();
    inner.message.body = Bytes(body_size);
    crypto::random_fill(inner.message.body);
    return inner;
}

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

Error error_named(const std::string& name)
{
    if (name == "wrong_key") {
        return Error::wrong_key;
    }
    if (name == "weak_key") {
        return Error::weak_key;
    }
    if (name == "authentication_failed") {
        return Error::authentication_failed;
    }
    if (name == "malformed") {
        return Error::malformed;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

struct VectorKey {
    std::uint32_t id = 0;
    crypto::X25519KeyPair keys;
};

VectorKey vector_key(const nlohmann::json& vectors)
{
    const auto& key = vectors.at("seal_key");
    auto keys = must(crypto::x25519_from_secret(SecretBytes::copy_of(hex_field(key, "secret"))));
    if (test::to_hex(keys.public_key) != key.at("public").get<std::string>()) {
        throw std::runtime_error("the seal key of the vectors does not match its secret");
    }
    return VectorKey{.id = key.at("id").get<std::uint32_t>(), .keys = std::move(keys)};
}

TEST(Seal, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/seal.json");
    const auto key = vector_key(vectors);
    const auto published = published_seal_key(key.id, key.keys.public_key);
    int cases = 0;
    for (const auto& entry : vectors.at("cases")) {
        const auto name = entry.at("name").get<std::string>();
        const auto inner = must(wire::decode(hex_field(entry, "inner"), wire::read_inner));
        test::RandomStream random(entry.at("random_seed").get<std::string>());
        const detail::RandomSource source = std::ref(random);
        const auto sealed = detail::seal(published, inner, source);
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(sealed->box.size(), entry.at("padded_size").get<std::size_t>() + crypto::aead_tag_size) << name;
        EXPECT_EQ(test::to_hex(wire::encode(*sealed)), entry.at("envelope").get<std::string>()) << name;

        const auto envelope = must(wire::decode(hex_field(entry, "envelope"), wire::read_seal));
        const auto opened = open(key.id, key.keys, envelope);
        ASSERT_TRUE(opened.has_value()) << name;
        EXPECT_TRUE(*opened == inner) << name;
        ++cases;
    }
    EXPECT_EQ(cases, 3);
}

TEST(Seal, RefusesTheLumeRefusals)
{
    const auto vectors = test::load_vectors("lume/seal.json");
    const auto key = vector_key(vectors);
    int refusals = 0;
    for (const auto& entry : vectors.at("refusals")) {
        const auto name = entry.at("name").get<std::string>();
        const auto envelope = wire::decode(hex_field(entry, "envelope"), wire::read_seal);
        ASSERT_TRUE(envelope.has_value()) << name;
        const auto opened = open(key.id, key.keys, *envelope);
        ASSERT_FALSE(opened.has_value()) << name;
        EXPECT_EQ(opened.error(), error_named(entry.at("error").get<std::string>())) << name;
        ++refusals;
    }
    EXPECT_EQ(refusals, 9);
}

TEST(Seal, OpensWhatItSeals)
{
    const auto bob = new_recipient(7);
    for (const bool with_initial : {false, true}) {
        const auto inner = inner_with(100, with_initial);
        const auto sealed = seal(bob.published, inner);
        ASSERT_TRUE(sealed.has_value());
        EXPECT_EQ(sealed->ssk_id, 7U);
        EXPECT_EQ(sealed->box.size(), padding_buckets.front() + crypto::aead_tag_size);
        const auto opened = open(7, bob.keys, *sealed);
        ASSERT_TRUE(opened.has_value());
        EXPECT_TRUE(*opened == inner);
    }
}

TEST(Seal, EveryEnvelopeIsFresh)
{
    const auto bob = new_recipient(7);
    const auto inner = inner_with(100, false);
    const auto first = must(seal(bob.published, inner));
    const auto second = must(seal(bob.published, inner));
    EXPECT_NE(first.ephemeral_key, second.ephemeral_key);
    EXPECT_NE(first.nonce, second.nonce);
    EXPECT_NE(first.box, second.box);
}

TEST(Seal, RefusesKeysThatAreNotSealKeys)
{
    auto bob = new_recipient(7);
    const auto inner = inner_with(100, false);
    for (const auto kind : {wire::PrekeyKind::signed_prekey, wire::PrekeyKind::one_time_prekey}) {
        bob.published.kind = kind;
        EXPECT_EQ(seal(bob.published, inner).error(), Error::not_a_seal_key);
    }
}

TEST(Seal, RefusesWeakSealKeys)
{
    auto bob = new_recipient(7);
    const auto inner = inner_with(100, false);
    bob.published.key = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    EXPECT_EQ(seal(bob.published, inner).error(), Error::weak_key);
    bob.published.key = {};
    EXPECT_EQ(seal(bob.published, inner).error(), Error::weak_key);
}

TEST(Seal, RefusesASenderThatIsNotTheInitiator)
{
    const auto bob = new_recipient(7);
    auto inner = inner_with(100, true);
    inner.sender.front() = static_cast<std::uint8_t>(inner.sender.front() ^ 0x01U);
    EXPECT_EQ(seal(bob.published, inner).error(), Error::malformed);
}

TEST(Seal, RefusesAnInnerLargerThanTheLargestBucket)
{
    const auto bob = new_recipient(7);
    EXPECT_EQ(seal(bob.published, inner_with(wire::ratchet_body_bound, true)).error(), Error::too_long);
    const auto largest = seal(bob.published, inner_with(wire::ratchet_body_bound, false));
    ASSERT_TRUE(largest.has_value());
    EXPECT_EQ(largest->box.size(), wire::seal_box_bound);
}

TEST(Seal, TheLargestContentFitsTheLargestEnvelope)
{
    wire::Content content;
    content.body = Bytes(wire::content_body_bound);
    wire::Introduction introduction;
    introduction.certificate = wire::UsernameCertificate{.username = std::string(wire::username_bound, 'a')};
    content.introduction = introduction;
    const auto plaintext_size = wire::encode(content).size();
    EXPECT_LE(plaintext_size, ratchet::max_plaintext_size);

    const auto bob = new_recipient(7);
    const auto sealed = seal(bob.published, inner_with(plaintext_size + crypto::aead_overhead, true));
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->box.size(), wire::seal_box_bound);
}

TEST(Seal, OpensOnlyWithTheKeyItWasSealedTo)
{
    const auto bob = new_recipient(7);
    const auto sealed = must(seal(bob.published, inner_with(100, false)));
    EXPECT_EQ(open(8, bob.keys, sealed).error(), Error::wrong_key);
    EXPECT_EQ(open(7, crypto::x25519_generate(), sealed).error(), Error::authentication_failed);
}

TEST(Seal, PaddedPlaintextMustBeExactlyAPaddedInner)
{
    const auto inner = inner_with(100, true);
    const auto encoded = wire::encode(inner);
    const auto padded = must(pad(encoded));
    const auto opened = detail::inner_of(padded);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(*opened == inner);
    EXPECT_EQ(detail::inner_of(encoded).error(), Error::authentication_failed);

    auto with_trailing_byte = encoded;
    with_trailing_byte.push_back(0x00);
    EXPECT_EQ(detail::inner_of(must(pad(with_trailing_byte))).error(), Error::malformed);
}

RC_GTEST_PROP(SealProperties, RoundTripsAnyInner, ())
{
    const auto bob = new_recipient(*rc::gen::arbitrary<std::uint32_t>());
    wire::Inner inner;
    inner.sender = crypto::random_public_bytes<wire::ed25519_key_size>();
    if (*rc::gen::arbitrary<bool>()) {
        wire::InitialHeader initial;
        initial.ik_sig = inner.sender;
        inner.initial = initial;
    }
    inner.message.body = *rc::gen::container<Bytes>(rc::gen::arbitrary<std::uint8_t>());

    const auto sealed = seal(bob.published, inner);
    RC_ASSERT(sealed.has_value());
    RC_ASSERT(sealed->box.size() == padded_size(wire::encode(inner).size()).value_or(0) + crypto::aead_tag_size);
    const auto opened = open(bob.published.id, bob.keys, *sealed);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(*opened == inner);
}

RC_GTEST_PROP(SealProperties, AnyChangedBitIsRefused, ())
{
    const auto bob = new_recipient(7);
    const auto envelope = wire::encode(must(seal(bob.published, inner_with(100, *rc::gen::arbitrary<bool>()))));
    const auto changed = wire::decode(test::flip_random_bit(envelope), wire::read_seal);
    if (changed) {
        RC_ASSERT_FALSE(open(7, bob.keys, *changed).has_value());
    }
}

}
}
