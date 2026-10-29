// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/seal.hpp"

#include "lume/crypto/aead.hpp"
#include "lume/crypto/random.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/identity.hpp"
#include "lume/identity/phrase.hpp"
#include "lume/ratchet/ratchet.hpp"
#include "lume/seal/padding.hpp"
#include "seal/seal_internal.hpp"
#include "support/expected.hpp"
#include "support/mutate.hpp"
#include "support/random_stream.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
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

constexpr std::uint64_t now = 1'800'000'000;
constexpr crypto::ByteArray<crypto::x25519_key_size> field_prime{
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
constexpr crypto::ByteArray<crypto::x25519_key_size> unreduced_base_point{
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

template <typename T, typename E>
T must(std::expected<T, E> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

template <std::size_t Size>
crypto::ByteArray<Size> array_of(const Bytes& bytes)
{
    if (bytes.size() != Size) {
        throw std::runtime_error("a vector field has the wrong length");
    }
    crypto::ByteArray<Size> array{};
    std::ranges::copy(bytes, array.begin());
    return array;
}

Recipient recipient_for(
    const identity::Identity& owner, std::uint32_t id, crypto::ByteView public_key, std::uint64_t created_at = now,
    wire::PrekeyKind kind = wire::PrekeyKind::seal_key, std::uint32_t generation = identity::first_generation)
{
    const handshake::PrekeyFacts facts{.kind = kind, .id = id, .created_at = created_at, .generation = generation};
    return Recipient{
        .pin = handshake::Pin{.identity = identity::public_identity(owner), .generation = generation},
        .generation = generation,
        .seal_key = must(handshake::make_prekey_x(owner, facts, public_key))};
}

struct Bob {
    identity::Identity identity;
    crypto::X25519KeyPair keys;
    Recipient recipient;
};

Bob new_bob(std::uint32_t id)
{
    auto owner = must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
    auto keys = crypto::x25519_generate();
    auto recipient = recipient_for(owner, id, keys.public_key);
    return Bob{.identity = std::move(owner), .keys = std::move(keys), .recipient = recipient};
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
    Recipient recipient;
    crypto::X25519KeyPair keys;
    std::uint64_t now = 0;
};

VectorKey vector_key(const nlohmann::json& vectors)
{
    const auto& key = vectors.at("seal_key");
    auto keys = must(crypto::x25519_from_secret(SecretBytes::copy_of(hex_field(key, "secret"))));
    if (test::to_hex(keys.public_key) != key.at("public").get<std::string>()) {
        throw std::runtime_error("the seal key of the vectors does not match its secret");
    }
    const auto generation = key.at("generation").get<std::uint32_t>();
    const Recipient recipient{
        .pin = handshake::Pin{
            .identity = identity::PublicIdentity{
                .signing_key = array_of<wire::ed25519_key_size>(hex_field(key, "signer")),
                .exchange_key = {},
                .binding = {}},
            .generation = generation},
        .generation = generation,
        .seal_key = wire::PrekeyX{
            .kind = wire::PrekeyKind::seal_key,
            .id = key.at("id").get<std::uint32_t>(),
            .created_at = key.at("created_at").get<std::uint64_t>(),
            .key = keys.public_key,
            .signature = array_of<wire::signature_size>(hex_field(key, "signature"))}};
    return VectorKey{.recipient = recipient, .keys = std::move(keys), .now = vectors.at("now").get<std::uint64_t>()};
}

TEST(Seal, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/seal.json");
    const auto key = vector_key(vectors);
    int cases = 0;
    for (const auto& entry : vectors.at("cases")) {
        const auto name = entry.at("name").get<std::string>();
        const auto inner = must(wire::decode(hex_field(entry, "inner"), wire::read_inner));
        test::RandomStream random(entry.at("random_seed").get<std::string>());
        const detail::RandomSource source = std::ref(random);
        const auto sealed = detail::seal(key.recipient, inner, key.now, source);
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(sealed->box.size(), entry.at("padded_size").get<std::size_t>() + crypto::aead_tag_size) << name;
        EXPECT_EQ(test::to_hex(wire::encode(*sealed)), entry.at("envelope").get<std::string>()) << name;

        const auto envelope = must(wire::decode(hex_field(entry, "envelope"), wire::read_seal));
        const auto opened = open(key.recipient.seal_key.id, key.keys, envelope);
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
        const auto opened = open(key.recipient.seal_key.id, key.keys, *envelope);
        EXPECT_EQ(test::error_of(opened), error_named(entry.at("error").get<std::string>())) << name;
        ++refusals;
    }
    EXPECT_EQ(refusals, 11);
}

TEST(Seal, OpensWhatItSeals)
{
    const auto bob = new_bob(7);
    for (const bool with_initial : {false, true}) {
        const auto inner = inner_with(100, with_initial);
        const auto sealed = seal(bob.recipient, inner, now);
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
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);
    const auto first = must(seal(bob.recipient, inner, now));
    const auto second = must(seal(bob.recipient, inner, now));
    EXPECT_NE(first.ephemeral_key, second.ephemeral_key);
    EXPECT_NE(first.nonce, second.nonce);
    EXPECT_NE(first.box, second.box);
}

TEST(Seal, RefusesKeysThatAreNotSealKeys)
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);
    const auto signed_prekey = recipient_for(bob.identity, 7, bob.keys.public_key, now, wire::PrekeyKind::signed_prekey);
    EXPECT_EQ(test::error_of(seal(signed_prekey, inner, now)), Error::not_a_seal_key);
    const auto one_time = recipient_for(bob.identity, 7, bob.keys.public_key, now, wire::PrekeyKind::one_time_prekey);
    EXPECT_EQ(test::error_of(seal(one_time, inner, now)), Error::not_a_seal_key);
}

TEST(Seal, RefusesSealKeysItCannotVerify)
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);

    auto forged = bob.recipient;
    auto signature = forged.seal_key.signature.value_or(crypto::ByteArray<wire::signature_size>{});
    signature.front() = static_cast<std::uint8_t>(signature.front() ^ 0x01U);
    forged.seal_key.signature = signature;
    EXPECT_EQ(test::error_of(seal(forged, inner, now)), Error::invalid_signature);

    auto other_key = bob.recipient;
    other_key.seal_key.key = crypto::x25519_generate().public_key;
    EXPECT_EQ(test::error_of(seal(other_key, inner, now)), Error::invalid_signature);

    auto other_generation = bob.recipient;
    other_generation.generation = identity::first_generation + 1;
    EXPECT_EQ(test::error_of(seal(other_generation, inner, now)), Error::invalid_signature);

    auto other_signer = bob.recipient;
    const auto stranger = must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
    other_signer.pin.identity.signing_key = identity::public_identity(stranger).signing_key;
    EXPECT_EQ(test::error_of(seal(other_signer, inner, now)), Error::invalid_signature);

    auto unsigned_key = bob.recipient;
    unsigned_key.seal_key.signature.reset();
    EXPECT_EQ(test::error_of(seal(unsigned_key, inner, now)), Error::invalid_signature);
}

TEST(Seal, HoldsSealKeysToThePinnedGeneration)
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);
    const auto key_of_generation = [&bob](std::uint32_t generation) {
        return recipient_for(bob.identity, 7, bob.keys.public_key, now, wire::PrekeyKind::seal_key, generation);
    };

    auto older = key_of_generation(1);
    older.pin.generation = 2;
    EXPECT_EQ(test::error_of(seal(older, inner, now)), Error::generation_went_down);

    auto newer = key_of_generation(2);
    newer.pin.generation = 1;
    EXPECT_EQ(test::error_of(seal(newer, inner, now)), Error::generation_went_up);

    auto claims_newer = key_of_generation(1);
    claims_newer.generation = 2;
    EXPECT_EQ(test::error_of(seal(claims_newer, inner, now)), Error::invalid_signature);

    EXPECT_TRUE(seal(key_of_generation(2), inner, now).has_value());
}

TEST(Seal, RefusesSealKeysOutsideTheirWindow)
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);
    const auto created = [&bob](std::uint64_t created_at) {
        return recipient_for(bob.identity, 7, bob.keys.public_key, created_at);
    };
    EXPECT_TRUE(seal(created(now + handshake::allowed_clock_skew), inner, now).has_value());
    EXPECT_EQ(test::error_of(seal(created(now + handshake::allowed_clock_skew + 1), inner, now)), Error::key_not_usable);
    EXPECT_TRUE(seal(created(now - handshake::rotating_key_usable_for), inner, now).has_value());
    EXPECT_EQ(
        test::error_of(seal(created(now - handshake::rotating_key_usable_for - 1), inner, now)), Error::key_not_usable);
}

TEST(Seal, RefusesWeakSealKeys)
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, false);
    auto top_bit = bob.keys.public_key;
    top_bit.back() = static_cast<std::uint8_t>(top_bit.back() | 0x80U);
    for (const auto& weak : {top_bit, unreduced_base_point, field_prime, crypto::ByteArray<crypto::x25519_key_size>{}}) {
        const auto recipient = recipient_for(bob.identity, 7, weak);
        EXPECT_EQ(test::error_of(seal(recipient, inner, now)), Error::weak_key) << test::to_hex(weak);
    }
}

TEST(Seal, RefusesASenderThatIsNotTheInitiator)
{
    const auto bob = new_bob(7);
    auto inner = inner_with(100, true);
    inner.sender.front() = static_cast<std::uint8_t>(inner.sender.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(seal(bob.recipient, inner, now)), Error::malformed);
}

TEST(Seal, RefusesAnInnerItCouldNotEncode)
{
    const auto bob = new_bob(7);
    auto inner = inner_with(100, true);
    auto initial = inner.initial.value_or(wire::InitialHeader{});
    for (const auto kind : {wire::PrekeyKind::signed_prekey, wire::PrekeyKind::seal_key}) {
        initial.pq_kind = kind;
        inner.initial = initial;
        EXPECT_EQ(test::error_of(seal(bob.recipient, inner, now)), Error::malformed);
    }
}

TEST(Seal, RefusesAnInnerLargerThanTheLargestBucket)
{
    const auto bob = new_bob(7);
    EXPECT_EQ(test::error_of(seal(bob.recipient, inner_with(wire::ratchet_body_bound, true), now)), Error::too_long);
    EXPECT_EQ(test::error_of(seal(bob.recipient, inner_with(wire::ratchet_body_bound + 1, false), now)), Error::too_long);
    const auto largest = seal(bob.recipient, inner_with(wire::ratchet_body_bound, false), now);
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

    const handshake::SessionKeys keys{
        .root_key = crypto::random_secret(32),
        .header_key_alice = crypto::random_secret(32),
        .next_header_key_bob = crypto::random_secret(32),
        .associated_data = Bytes(64)};
    auto alice = must(ratchet::start_as_alice(keys, crypto::x25519_generate().public_key));
    const auto message = ratchet::encrypt(alice, wire::encode(content));
    ASSERT_TRUE(message.has_value());

    auto inner = inner_with(0, true);
    inner.message = *message;
    const auto bob = new_bob(7);
    const auto sealed = seal(bob.recipient, inner, now);
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->box.size(), wire::seal_box_bound);
    EXPECT_EQ(wire::encode(*sealed).size(), 1U + 4 + 32 + 24 + 4 + wire::seal_box_bound);
}

TEST(Seal, OpensOnlyWithTheKeyItWasSealedTo)
{
    const auto bob = new_bob(7);
    const auto sealed = must(seal(bob.recipient, inner_with(100, false), now));
    EXPECT_EQ(test::error_of(open(8, bob.keys, sealed)), Error::wrong_key);
    EXPECT_EQ(test::error_of(open(7, crypto::x25519_generate(), sealed)), Error::authentication_failed);
}

TEST(Seal, BlamesABrokenOwnKeyOnTheLibraryNotThePeer)
{
    const auto bob = new_bob(7);
    const auto sealed = must(seal(bob.recipient, inner_with(100, false), now));
    const crypto::X25519KeyPair broken{.public_key = bob.keys.public_key, .secret_key = SecretBytes(16)};
    EXPECT_EQ(test::error_of(open(7, broken, sealed)), Error::library_failure);
}

TEST(Seal, RefusesBoxesTooShortToAuthenticate)
{
    const auto bob = new_bob(7);
    auto sealed = must(seal(bob.recipient, inner_with(100, false), now));
    for (const std::size_t size : {crypto::aead_tag_size, crypto::aead_tag_size - 1, std::size_t{0}}) {
        sealed.box.resize(size);
        EXPECT_EQ(test::error_of(open(7, bob.keys, sealed)), Error::authentication_failed) << size;
    }
}

TEST(Seal, PaddedPlaintextMustBeExactlyAPaddedInner)
{
    const auto inner = inner_with(100, true);
    const auto encoded = wire::encode(inner);
    const auto padded = must(pad(encoded));
    const auto opened = detail::inner_of(padded);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(*opened == inner);
    EXPECT_EQ(test::error_of(detail::inner_of(encoded)), Error::authentication_failed);
    EXPECT_EQ(test::error_of(detail::inner_of(Bytes{})), Error::authentication_failed);

    auto with_trailing_byte = encoded;
    with_trailing_byte.push_back(0x00);
    EXPECT_EQ(test::error_of(detail::inner_of(must(pad(with_trailing_byte)))), Error::malformed);
}

RC_GTEST_PROP(SealProperties, RoundTripsAnyInner, ())
{
    const auto bob = new_bob(*rc::gen::arbitrary<std::uint32_t>());
    wire::Inner inner;
    inner.sender = crypto::random_public_bytes<wire::ed25519_key_size>();
    if (*rc::gen::arbitrary<bool>()) {
        wire::InitialHeader initial;
        initial.ik_sig = inner.sender;
        inner.initial = initial;
    }
    inner.message.body = *rc::gen::container<Bytes>(rc::gen::arbitrary<std::uint8_t>());

    const auto sealed = seal(bob.recipient, inner, now);
    RC_ASSERT(sealed.has_value());
    RC_ASSERT(sealed->box.size() == padded_size(wire::encode(inner).size()).value_or(0) + crypto::aead_tag_size);
    const auto opened = open(bob.recipient.seal_key.id, bob.keys, *sealed);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(*opened == inner);
}

RC_GTEST_PROP(SealProperties, AnyChangedBitIsRefused, ())
{
    const auto bob = new_bob(7);
    const auto inner = inner_with(100, *rc::gen::arbitrary<bool>());
    const auto envelope = wire::encode(must(seal(bob.recipient, inner, now)));
    const auto changed = wire::decode(test::flip_random_bit(envelope), wire::read_seal);
    if (changed) {
        RC_ASSERT_FALSE(open(7, bob.keys, *changed).has_value());
    }
}

}
}
