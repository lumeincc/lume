// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/card/card.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/random.hpp"
#include "lume/directory/directory.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/identity.hpp"
#include "lume/identity/phrase.hpp"
#include "lume/seal/seal.hpp"
#include "seal/seal_internal.hpp"
#include "support/expected.hpp"
#include "support/random_stream.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::card {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint64_t now = 1'800'003'600;
constexpr std::uint64_t skew = handshake::allowed_clock_skew;

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

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

identity::Identity identity_from(const nlohmann::json& entry)
{
    return must(identity::derive_identity(SecretBytes::copy_of(hex_field(entry, "entropy"))));
}

identity::Identity new_identity()
{
    return must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
}

struct Producer {
    identity::Identity identity = new_identity();
    crypto::X25519KeyPair spk = crypto::x25519_generate();
    crypto::MlKemKeyPair kem = crypto::mlkem768_generate();
    crypto::X25519KeyPair ssk = crypto::x25519_generate();
};

struct Ages {
    std::uint64_t spk = now;
    std::uint64_t pqspk = now;
    std::uint64_t ssk = now;
};

wire::Card unsigned_card(const Producer& producer, const Ages& ages = {})
{
    const auto facts = [](wire::PrekeyKind kind, std::uint32_t id, std::uint64_t created_at) {
        return handshake::PrekeyFacts{.kind = kind, .id = id, .created_at = created_at, .generation = 1};
    };
    const auto identity = identity::public_identity(producer.identity);
    wire::Card card;
    card.certificate.username = "bob";
    card.certificate.ik_sig = identity.signing_key;
    card.certificate.ik_dh = identity.exchange_key;
    card.bind = identity.binding;
    card.generation = 1;
    card.spk = must(handshake::make_prekey_x(
        producer.identity, facts(wire::PrekeyKind::signed_prekey, 1, ages.spk), producer.spk.public_key));
    card.pqspk = must(handshake::make_prekey_kem(
        producer.identity, facts(wire::PrekeyKind::kem_last_resort, 2, ages.pqspk), producer.kem.public_key));
    card.ssk = must(handshake::make_prekey_x(
        producer.identity, facts(wire::PrekeyKind::seal_key, 3, ages.ssk), producer.ssk.public_key));
    card.token = crypto::random_public_bytes<wire::token_size>();
    card.group_id = crypto::random_public_bytes<wire::group_id_size>();
    card.expires_at = now + card_lifetime;
    return card;
}

wire::Card signed_card(const Producer& producer, const identity::Identity& recipient, wire::Card card)
{
    return must(sign_card(producer.identity, std::move(card), identity::public_identity(recipient).signing_key));
}

Error refusal_of(const Producer& producer, const identity::Identity& recipient, wire::Card card,
    const std::optional<handshake::Pin>& pinned = std::nullopt)
{
    const auto signed_one = signed_card(producer, recipient, std::move(card));
    return test::error_of(check_card(signed_one, identity::public_identity(recipient).signing_key, now, pinned));
}

seal::Recipient recipient_for(const identity::Identity& owner, const crypto::X25519KeyPair& keys, std::uint64_t created_at)
{
    const handshake::PrekeyFacts facts{
        .kind = wire::PrekeyKind::seal_key, .id = 9, .created_at = created_at, .generation = 1};
    return seal::Recipient{
        .pin = handshake::Pin{.identity = identity::public_identity(owner), .generation = 1},
        .generation = 1,
        .seal_key = must(handshake::make_prekey_x(owner, facts, keys.public_key))};
}

TEST(Card, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/card.json");
    const auto identities = test::load_vectors("lume/identity.json").at("cases");
    const auto at = vectors.at("now").get<std::uint64_t>();
    const auto bob = identity_from(identities.at(vectors.at("producer").get<std::size_t>()));
    const auto alice = identity_from(identities.at(vectors.at("recipient").get<std::size_t>()));
    const auto alice_key = identity::public_identity(alice).signing_key;

    const auto& card_vector = vectors.at("card");
    const auto card = must(wire::decode(hex_field(card_vector, "encoded"), wire::read_card));
    EXPECT_EQ(test::to_hex(wire::encode(card.certificate)), card_vector.at("certificate").get<std::string>());
    EXPECT_EQ(test::to_hex(card.token), card_vector.at("token").get<std::string>());
    EXPECT_EQ(test::to_hex(card.group_id), card_vector.at("group_id").get<std::string>());
    EXPECT_EQ(card.expires_at, card_vector.at("expires_at").get<std::uint64_t>());
    EXPECT_EQ(test::to_hex(card_message(alice_key, card)), card_vector.at("message").get<std::string>());
    auto unsigned_one = card;
    unsigned_one.signature = {};
    EXPECT_EQ(test::to_hex(must(sign_card(bob, unsigned_one, alice_key)).signature),
        card_vector.at("signature").get<std::string>());
    EXPECT_EQ(test::to_hex(wire::encode(card)), card_vector.at("encoded").get<std::string>());

    const auto bundle = check_card(card, alice_key, at, std::nullopt);
    ASSERT_TRUE(bundle.has_value());
    EXPECT_EQ(bundle->identity.signing_key, identity::public_identity(bob).signing_key);
    EXPECT_EQ(bundle->identity.exchange_key, identity::public_identity(bob).exchange_key);
    EXPECT_TRUE(handshake::initiate(alice, *bundle, std::nullopt, at).has_value());

    const auto directory_vectors = test::load_vectors("lume/directory.json");
    directory::Directory names(array_of<wire::ed25519_key_size>(hex_field(directory_vectors.at("root"), "public")));
    ASSERT_TRUE(names
                    .accept(must(wire::decode(hex_field(directory_vectors.at("list"), "encoded"), wire::read_directory_keys)),
                        at)
                    .has_value());
    EXPECT_TRUE(
        names.check_certificate(card.certificate, at, bundle->identity, card.certificate.account_id).has_value());

    const auto& seal_vector = vectors.at("recipient_seal_key");
    const auto keys = must(crypto::x25519_from_secret(SecretBytes::copy_of(hex_field(seal_vector, "secret"))));
    ASSERT_EQ(test::to_hex(keys.public_key), seal_vector.at("public").get<std::string>());
    const seal::Recipient recipient{
        .pin = handshake::Pin{.identity = identity::public_identity(alice), .generation = 1},
        .generation = seal_vector.at("generation").get<std::uint32_t>(),
        .seal_key = wire::PrekeyX{
            .kind = wire::PrekeyKind::seal_key,
            .id = seal_vector.at("id").get<std::uint32_t>(),
            .created_at = seal_vector.at("created_at").get<std::uint64_t>(),
            .key = keys.public_key,
            .signature = array_of<wire::signature_size>(hex_field(seal_vector, "signature"))}};
    test::RandomStream random(vectors.at("random_seed").get<std::string>());
    const seal::detail::RandomSource source = std::ref(random);
    const auto sealed = seal::detail::seal_card(recipient, card, at, source);
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(test::to_hex(wire::encode(*sealed)), vectors.at("envelope").get<std::string>());

    const auto envelope = must(wire::decode(hex_field(vectors, "envelope"), wire::read_seal));
    const auto opened = seal::open_card(recipient.seal_key.id, keys, envelope);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(*opened == card);
    EXPECT_EQ(test::error_of(seal::open(recipient.seal_key.id, keys, envelope)), seal::Error::authentication_failed);
}

TEST(Card, CarriesEverythingAHandshakeNeeds)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto card = signed_card(bob, alice, unsigned_card(bob));
    const auto bundle = check_card(card, identity::public_identity(alice).signing_key, now, std::nullopt);
    ASSERT_TRUE(bundle.has_value());
    EXPECT_FALSE(bundle->one_time_prekey.has_value());
    EXPECT_TRUE(handshake::initiate(alice, *bundle, std::nullopt, now).has_value());
}

TEST(Card, RefusesCardsOutsideTheirTime)
{
    const Producer bob;
    const auto alice = new_identity();
    auto expires_now = unsigned_card(bob);
    expires_now.expires_at = now;
    EXPECT_EQ(refusal_of(bob, alice, expires_now), Error::expired);

    auto longest = unsigned_card(bob);
    longest.expires_at = now + card_lifetime + skew;
    EXPECT_TRUE(check_card(signed_card(bob, alice, longest), identity::public_identity(alice).signing_key, now,
        std::nullopt)
                    .has_value());
    auto too_long = unsigned_card(bob);
    too_long.expires_at = now + card_lifetime + skew + 1;
    EXPECT_EQ(refusal_of(bob, alice, too_long), Error::bad_lifetime);
}

TEST(Card, IsBoundToItsRecipientAndItsContents)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto carol = new_identity();
    const auto card = signed_card(bob, alice, unsigned_card(bob));
    EXPECT_EQ(test::error_of(check_card(card, identity::public_identity(carol).signing_key, now, std::nullopt)),
        Error::invalid_signature);

    const auto alice_key = identity::public_identity(alice).signing_key;
    auto other_token = card;
    other_token.token.front() = static_cast<std::uint8_t>(other_token.token.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(check_card(other_token, alice_key, now, std::nullopt)), Error::invalid_signature);
    auto other_group = card;
    other_group.group_id.front() = static_cast<std::uint8_t>(other_group.group_id.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(check_card(other_group, alice_key, now, std::nullopt)), Error::invalid_signature);
    auto other_expiry = card;
    other_expiry.expires_at -= 1;
    EXPECT_EQ(test::error_of(check_card(other_expiry, alice_key, now, std::nullopt)), Error::invalid_signature);

    const Producer mallory;
    const auto by_someone_else = must(sign_card(mallory.identity, unsigned_card(bob), alice_key));
    EXPECT_EQ(test::error_of(check_card(by_someone_else, alice_key, now, std::nullopt)), Error::invalid_signature);
}

TEST(Card, NeverOutlivesTheKeysItCarries)
{
    const Producer bob;
    const auto alice = new_identity();
    const std::uint64_t oldest = now + card_lifetime - handshake::rotating_key_usable_for;
    EXPECT_TRUE(check_card(signed_card(bob, alice, unsigned_card(bob, Ages{.spk = oldest, .pqspk = oldest, .ssk = oldest})),
        identity::public_identity(alice).signing_key, now, std::nullopt)
                    .has_value());
    EXPECT_EQ(refusal_of(bob, alice, unsigned_card(bob, Ages{.spk = oldest - 1})), Error::outlives_its_keys);
    EXPECT_EQ(refusal_of(bob, alice, unsigned_card(bob, Ages{.pqspk = oldest - 1})), Error::outlives_its_keys);
    EXPECT_EQ(refusal_of(bob, alice, unsigned_card(bob, Ages{.ssk = oldest - 1})), Error::outlives_its_keys);
}

TEST(Card, ChecksItsKeysLikeABundle)
{
    const Producer bob;
    const auto alice = new_identity();
    auto forged_key = unsigned_card(bob);
    forged_key.spk.key = crypto::x25519_generate().public_key;
    EXPECT_EQ(refusal_of(bob, alice, forged_key), Error::invalid_keys);

    auto wrong_binding = unsigned_card(bob);
    wrong_binding.bind.front() = static_cast<std::uint8_t>(wrong_binding.bind.front() ^ 0x01U);
    EXPECT_EQ(refusal_of(bob, alice, wrong_binding), Error::invalid_keys);

    auto other_generation = unsigned_card(bob);
    other_generation.generation = 2;
    EXPECT_EQ(refusal_of(bob, alice, other_generation), Error::invalid_keys);

    const handshake::Pin someone_else{.identity = identity::public_identity(new_identity()), .generation = 1};
    EXPECT_EQ(refusal_of(bob, alice, unsigned_card(bob), someone_else), Error::identity_changed);
    const handshake::Pin later{.identity = identity::public_identity(bob.identity), .generation = 2};
    EXPECT_EQ(refusal_of(bob, alice, unsigned_card(bob), later), Error::generation_went_down);
}

TEST(CardSeal, AcceptsASealKeyUpToThirtyDaysOld)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto keys = crypto::x25519_generate();
    const auto card = signed_card(bob, alice, unsigned_card(bob));

    const auto twenty_days = recipient_for(alice, keys, now - (20 * day));
    const auto sealed = seal::seal_card(twenty_days, card, now);
    ASSERT_TRUE(sealed.has_value());
    const auto opened = seal::open_card(twenty_days.seal_key.id, keys, *sealed);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(*opened == card);

    wire::Inner inner;
    inner.message.body = Bytes(10);
    EXPECT_EQ(test::error_of(seal::seal(twenty_days, inner, now)), seal::Error::key_not_usable);

    EXPECT_TRUE(seal::seal_card(recipient_for(alice, keys, now - seal::card_seal_key_usable_for), card, now).has_value());
    EXPECT_EQ(test::error_of(seal::seal_card(recipient_for(alice, keys, now - seal::card_seal_key_usable_for - 1), card, now)),
        seal::Error::key_not_usable);
}

TEST(CardSeal, CardsAndMessagesNeverOpenAsEachOther)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto keys = crypto::x25519_generate();
    const auto recipient = recipient_for(alice, keys, now);
    const auto sealed_card = must(seal::seal_card(recipient, signed_card(bob, alice, unsigned_card(bob)), now));
    EXPECT_EQ(test::error_of(seal::open(recipient.seal_key.id, keys, sealed_card)), seal::Error::authentication_failed);

    wire::Inner inner;
    inner.message.body = Bytes(10);
    const auto sealed_message = must(seal::seal(recipient, inner, now));
    EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id, keys, sealed_message)),
        seal::Error::authentication_failed);
}

TEST(CardSeal, RefusesWhatItCannotSealOrOpen)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto keys = crypto::x25519_generate();
    const auto recipient = recipient_for(alice, keys, now);
    auto unsigned_ssk = signed_card(bob, alice, unsigned_card(bob));
    unsigned_ssk.ssk.signature.reset();
    EXPECT_EQ(test::error_of(seal::seal_card(recipient, unsigned_ssk, now)), seal::Error::malformed);
    auto wrong_kind = signed_card(bob, alice, unsigned_card(bob));
    wrong_kind.spk.kind = wire::PrekeyKind::seal_key;
    EXPECT_EQ(test::error_of(seal::seal_card(recipient, wrong_kind, now)), seal::Error::malformed);

    auto sealed = must(seal::seal_card(recipient, signed_card(bob, alice, unsigned_card(bob)), now));
    EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id + 1, keys, sealed)), seal::Error::wrong_key);
    sealed.box.back() = static_cast<std::uint8_t>(sealed.box.back() ^ 0x01U);
    EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id, keys, sealed)), seal::Error::authentication_failed);
}

}
}
