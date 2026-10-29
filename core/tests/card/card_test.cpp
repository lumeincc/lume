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
#include <limits>
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
constexpr std::uint64_t usable_for = handshake::rotating_key_usable_for;

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

SigningKey signing_key_of(const identity::Identity& owner)
{
    return identity::public_identity(owner).signing_key;
}

struct Producer {
    identity::Identity identity = new_identity();
    crypto::X25519KeyPair spk = crypto::x25519_generate();
    crypto::MlKemKeyPair kem = crypto::mlkem768_generate();
    crypto::X25519KeyPair ssk = crypto::x25519_generate();
};

struct Keys {
    std::uint64_t spk = now;
    std::uint64_t pqspk = now;
    std::uint64_t ssk = now;
    std::uint32_t generation = 1;
    wire::PrekeyKind pq_kind = wire::PrekeyKind::kem_last_resort;
};

wire::Card unsigned_card(const Producer& producer, const Keys& keys = {})
{
    const auto facts = [&keys](wire::PrekeyKind kind, std::uint32_t id, std::uint64_t created_at) {
        return handshake::PrekeyFacts{.kind = kind, .id = id, .created_at = created_at, .generation = keys.generation};
    };
    const auto identity = identity::public_identity(producer.identity);
    wire::Card card;
    card.certificate.username = "bob";
    card.certificate.ik_sig = identity.signing_key;
    card.certificate.ik_dh = identity.exchange_key;
    card.bind = identity.binding;
    card.generation = keys.generation;
    card.spk = must(handshake::make_prekey_x(
        producer.identity, facts(wire::PrekeyKind::signed_prekey, 1, keys.spk), producer.spk.public_key));
    card.pqspk = must(handshake::make_prekey_kem(producer.identity, facts(keys.pq_kind, 2, keys.pqspk), producer.kem.public_key));
    card.ssk = must(handshake::make_prekey_x(
        producer.identity, facts(wire::PrekeyKind::seal_key, 3, keys.ssk), producer.ssk.public_key));
    card.token = crypto::random_public_bytes<wire::token_size>();
    card.group_id = crypto::random_public_bytes<wire::group_id_size>();
    card.expires_at = now + card_lifetime;
    return card;
}

wire::Card signed_card(const Producer& producer, const identity::Identity& recipient, wire::Card card)
{
    return must(sign_card(producer.identity, std::move(card), signing_key_of(recipient), now));
}

wire::Card signed_as_is(const Producer& producer, const identity::Identity& recipient, wire::Card card)
{
    card.signature = must(crypto::ed25519_sign(producer.identity.signing.seed, card_message(signing_key_of(recipient), card)));
    return card;
}

Member member_of(const identity::Identity& owner)
{
    const auto identity = identity::public_identity(owner);
    return Member{.signing_key = identity.signing_key, .exchange_key = identity.exchange_key};
}

Expected expected_for(const identity::Identity& recipient, const wire::Card& card)
{
    return Expected{
        .recipient = signing_key_of(recipient),
        .group_id = card.group_id,
        .member = Member{.signing_key = card.certificate.ik_sig, .exchange_key = card.certificate.ik_dh}};
}

const directory::Directory& no_names()
{
    static const directory::Directory empty(crypto::ByteArray<wire::ed25519_key_size>{});
    return empty;
}

Result<CheckedCard> checked(
    const wire::Card& card, const identity::Identity& recipient, const std::optional<handshake::Pin>& pinned = std::nullopt)
{
    return check_card(card, expected_for(recipient, card), now, pinned, no_names());
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

Error error_named(const std::string& name)
{
    if (name == "expired") {
        return Error::expired;
    }
    if (name == "bad_lifetime") {
        return Error::bad_lifetime;
    }
    if (name == "outlives_its_keys") {
        return Error::outlives_its_keys;
    }
    if (name == "wrong_group") {
        return Error::wrong_group;
    }
    if (name == "wrong_member") {
        return Error::wrong_member;
    }
    if (name == "invalid_signature") {
        return Error::invalid_signature;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

seal::Error seal_error_named(const std::string& name)
{
    if (name == "authentication_failed") {
        return seal::Error::authentication_failed;
    }
    if (name == "malformed") {
        return seal::Error::malformed;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

TEST(Card, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/card.json");
    const auto identities = test::load_vectors("lume/identity.json").at("cases");
    const auto at = vectors.at("now").get<std::uint64_t>();
    const auto bob = identity_from(identities.at(vectors.at("producer").get<std::size_t>()));
    const auto alice = identity_from(identities.at(vectors.at("recipient").get<std::size_t>()));

    const auto& card_vector = vectors.at("card");
    const auto card = must(wire::decode(hex_field(card_vector, "encoded"), wire::read_card));
    EXPECT_EQ(test::to_hex(wire::encode(card.certificate)), card_vector.at("certificate").get<std::string>());
    EXPECT_EQ(test::to_hex(card.token), card_vector.at("token").get<std::string>());
    EXPECT_EQ(test::to_hex(card.group_id), card_vector.at("group_id").get<std::string>());
    EXPECT_EQ(card.expires_at, card_vector.at("expires_at").get<std::uint64_t>());
    EXPECT_EQ(test::to_hex(card_message(signing_key_of(alice), card)), card_vector.at("message").get<std::string>());
    auto unsigned_one = card;
    unsigned_one.signature = {};
    unsigned_one.expires_at = 0;
    const auto resigned = must(sign_card(bob, unsigned_one, signing_key_of(alice), at));
    EXPECT_EQ(resigned.expires_at, card.expires_at);
    EXPECT_EQ(test::to_hex(resigned.signature), card_vector.at("signature").get<std::string>());
    EXPECT_EQ(test::to_hex(wire::encode(card)), card_vector.at("encoded").get<std::string>());

    const auto directory_vectors = test::load_vectors("lume/directory.json");
    directory::Directory names(array_of<wire::ed25519_key_size>(hex_field(directory_vectors.at("root"), "public")));
    ASSERT_TRUE(
        names.accept(must(wire::decode(hex_field(directory_vectors.at("list"), "encoded"), wire::read_directory_keys)), at)
            .has_value());
    const Expected expected{.recipient = signing_key_of(alice), .group_id = card.group_id, .member = member_of(bob)};
    const auto checked_card = check_card(card, expected, at, std::nullopt, names);
    ASSERT_TRUE(checked_card.has_value());
    EXPECT_TRUE(checked_card->name_check.has_value());
    EXPECT_EQ(checked_card->bundle.identity.exchange_key, identity::public_identity(bob).exchange_key);
    EXPECT_TRUE(handshake::initiate(alice, checked_card->bundle, std::nullopt, at).has_value());

    int check_refusals = 0;
    for (const auto& refusal : vectors.at("check_refusals")) {
        const Expected other{
            .recipient = array_of<wire::ed25519_key_size>(hex_field(refusal, "recipient")),
            .group_id = array_of<wire::group_id_size>(hex_field(refusal, "group_id")),
            .member = Member{
                .signing_key = array_of<wire::ed25519_key_size>(hex_field(refusal, "member_ik_sig")),
                .exchange_key = array_of<wire::x25519_key_size>(hex_field(refusal, "member_ik_dh"))}};
        const auto refused =
            refusal.contains("card") ? must(wire::decode(hex_field(refusal, "card"), wire::read_card)) : card;
        const auto when = refusal.at("now").get<std::uint64_t>();
        EXPECT_EQ(test::error_of(check_card(refused, other, when, std::nullopt, names)),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++check_refusals;
    }
    EXPECT_EQ(check_refusals, 7);

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

    int envelope_refusals = 0;
    for (const auto& refusal : vectors.at("envelope_refusals")) {
        const auto refused = must(wire::decode(hex_field(refusal, "envelope"), wire::read_seal));
        EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id, keys, refused)),
            seal_error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++envelope_refusals;
    }
    EXPECT_EQ(envelope_refusals, 2);
}

TEST(Card, CarriesEverythingAHandshakeNeeds)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto result = checked(signed_card(bob, alice, unsigned_card(bob)), alice);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(test::error_of(result->name_check), directory::Error::no_current_list);
    EXPECT_FALSE(result->bundle.one_time_prekey.has_value());
    EXPECT_TRUE(handshake::initiate(alice, result->bundle, std::nullopt, now).has_value());
}

TEST(Card, ChecksTheNameItCarries)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto root = crypto::ed25519_generate();
    const auto signer = crypto::ed25519_generate();
    wire::DirectoryKeys list;
    list.sequence = 1;
    list.issued_at = now - directory::day;
    list.expires_at = now + directory::day;
    list.keys.push_back(wire::DirectoryKey{
        .key_id = 1, .public_key = signer.public_key, .not_before = now - directory::day, .not_after = now + (60 * directory::day)});
    list.signature = must(crypto::ed25519_sign(root.seed, directory::list_message(list)));
    directory::Directory names(root.public_key);
    ASSERT_TRUE(names.accept(list, now).has_value());

    auto card = unsigned_card(bob);
    card.certificate.key_id = 1;
    card.certificate.generation = 1;
    card.certificate.issued_at = now - 60;
    card.certificate.expires_at = now + (30 * directory::day) - 60;
    card.certificate.signature = must(crypto::ed25519_sign(signer.seed, directory::certificate_message(card.certificate)));
    const auto genuine = signed_card(bob, alice, card);
    const auto verified = check_card(genuine, expected_for(alice, genuine), now, std::nullopt, names);
    ASSERT_TRUE(verified.has_value());
    EXPECT_TRUE(verified->name_check.has_value());

    auto impostor = card;
    impostor.certificate.username = "admin";
    const auto shown = signed_card(bob, alice, impostor);
    const auto unverified = check_card(shown, expected_for(alice, shown), now, std::nullopt, names);
    ASSERT_TRUE(unverified.has_value());
    EXPECT_EQ(test::error_of(unverified->name_check), directory::Error::invalid_signature);

    const auto after_the_list = check_card(genuine, expected_for(alice, genuine), now + (2 * directory::day), std::nullopt, names);
    ASSERT_TRUE(after_the_list.has_value());
    EXPECT_EQ(test::error_of(after_the_list->name_check), directory::Error::no_current_list);
}

TEST(Card, IsBoundToItsGroupAndItsMember)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto card = signed_card(bob, alice, unsigned_card(bob));
    auto other_group = expected_for(alice, card);
    other_group.group_id.front() = static_cast<std::uint8_t>(other_group.group_id.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(check_card(card, other_group, now, std::nullopt, no_names())), Error::wrong_group);

    auto other_member = expected_for(alice, card);
    other_member.member = member_of(new_identity());
    EXPECT_EQ(test::error_of(check_card(card, other_member, now, std::nullopt, no_names())), Error::wrong_member);
    auto other_signing_key = expected_for(alice, card);
    other_signing_key.member.signing_key = signing_key_of(new_identity());
    EXPECT_EQ(test::error_of(check_card(card, other_signing_key, now, std::nullopt, no_names())), Error::wrong_member);
    auto other_exchange_key = expected_for(alice, card);
    other_exchange_key.member.exchange_key = member_of(new_identity()).exchange_key;
    EXPECT_EQ(test::error_of(check_card(card, other_exchange_key, now, std::nullopt, no_names())), Error::wrong_member);

    auto to_itself = expected_for(alice, card);
    to_itself.recipient = to_itself.member.signing_key;
    EXPECT_EQ(test::error_of(check_card(card, to_itself, now, std::nullopt, no_names())), Error::wrong_member);
    EXPECT_EQ(test::error_of(sign_card(bob.identity, unsigned_card(bob), signing_key_of(bob.identity), now)),
        Error::wrong_member);
    EXPECT_EQ(test::error_of(sign_card(bob.identity, unsigned_card(bob), SigningKey{}, now)), Error::wrong_member);
}

TEST(Card, ChecksInTheOrderTheSpecGives)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto refused = [](const wire::Card& card, const Expected& expected,
                             const std::optional<handshake::Pin>& pinned = std::nullopt) {
        return test::error_of(check_card(card, expected, now, pinned, no_names()));
    };
    auto forged = signed_card(bob, alice, unsigned_card(bob));
    forged.signature.front() = static_cast<std::uint8_t>(forged.signature.front() ^ 0x01U);
    auto other_group = expected_for(alice, forged);
    other_group.group_id.front() = static_cast<std::uint8_t>(other_group.group_id.front() ^ 0x01U);
    auto other_member = expected_for(alice, forged);
    other_member.member = member_of(new_identity());
    auto other_group_and_member = other_member;
    other_group_and_member.group_id = other_group.group_id;
    EXPECT_EQ(refused(forged, other_group), Error::wrong_group);
    EXPECT_EQ(refused(forged, other_member), Error::wrong_member);
    EXPECT_EQ(refused(forged, other_group_and_member), Error::wrong_group);

    auto too_long = unsigned_card(bob);
    too_long.expires_at = now + card_lifetime + skew + 1;
    auto too_long_elsewhere = expected_for(alice, too_long);
    too_long_elsewhere.group_id = other_group.group_id;
    EXPECT_EQ(refused(signed_as_is(bob, alice, too_long), too_long_elsewhere), Error::bad_lifetime);

    auto forged_with_a_wrong_kind = signed_as_is(bob, alice, unsigned_card(bob, Keys{.pq_kind = wire::PrekeyKind::kem_one_time}));
    forged_with_a_wrong_kind.signature.front() = static_cast<std::uint8_t>(forged_with_a_wrong_kind.signature.front() ^ 0x01U);
    EXPECT_EQ(refused(forged_with_a_wrong_kind, expected_for(alice, forged_with_a_wrong_kind)), Error::invalid_signature);

    const auto outliving = signed_as_is(bob, alice, unsigned_card(bob, Keys{.spk = now + card_lifetime - usable_for - 1}));
    const handshake::Pin someone_else{.identity = identity::public_identity(new_identity()), .generation = 1};
    EXPECT_EQ(refused(outliving, expected_for(alice, outliving)), Error::outlives_its_keys);
    EXPECT_EQ(refused(outliving, expected_for(alice, outliving), someone_else), Error::identity_changed);
}

TEST(Card, IsBoundToItsRecipientAndItsContents)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto carol = new_identity();
    const auto card = signed_card(bob, alice, unsigned_card(bob));
    EXPECT_EQ(test::error_of(checked(card, carol)), Error::invalid_signature);

    auto other_token = card;
    other_token.token.front() = static_cast<std::uint8_t>(other_token.token.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(checked(other_token, alice)), Error::invalid_signature);
    auto other_expiry = card;
    other_expiry.expires_at -= 1;
    EXPECT_EQ(test::error_of(checked(other_expiry, alice)), Error::invalid_signature);

    const Producer mallory;
    auto by_someone_else = unsigned_card(bob);
    by_someone_else.signature =
        must(crypto::ed25519_sign(mallory.identity.signing.seed, card_message(signing_key_of(alice), by_someone_else)));
    EXPECT_EQ(test::error_of(checked(by_someone_else, alice)), Error::invalid_signature);
}

TEST(Card, RefusesCardsOutsideTheirTime)
{
    const Producer bob;
    const auto alice = new_identity();
    auto expires_now = unsigned_card(bob);
    expires_now.expires_at = now;
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, expires_now), alice)), Error::expired);

    auto longest = unsigned_card(bob, Keys{.spk = now + skew, .pqspk = now + skew, .ssk = now + skew});
    longest.expires_at = now + card_lifetime + skew;
    EXPECT_TRUE(checked(signed_as_is(bob, alice, longest), alice).has_value());
    auto too_long = unsigned_card(bob);
    too_long.expires_at = now + card_lifetime + skew + 1;
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, too_long), alice)), Error::bad_lifetime);

    auto expired_elsewhere = unsigned_card(bob);
    expired_elsewhere.expires_at = now;
    auto in_another_group = expected_for(alice, expired_elsewhere);
    in_another_group.group_id.front() = static_cast<std::uint8_t>(in_another_group.group_id.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(check_card(signed_as_is(bob, alice, expired_elsewhere), in_another_group, now,
                  std::nullopt, no_names())),
        Error::expired);
}

TEST(Card, NeverOutlivesTheKeysItCarries)
{
    const Producer bob;
    const auto alice = new_identity();
    const std::uint64_t oldest = now + card_lifetime - usable_for;
    EXPECT_TRUE(checked(signed_as_is(bob, alice, unsigned_card(bob, Keys{.spk = oldest, .pqspk = oldest, .ssk = oldest})),
        alice)
                    .has_value());
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, unsigned_card(bob, Keys{.spk = oldest - 1})), alice)),
        Error::outlives_its_keys);
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, unsigned_card(bob, Keys{.pqspk = oldest - 1})), alice)),
        Error::outlives_its_keys);
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, unsigned_card(bob, Keys{.ssk = oldest - 1})), alice)),
        Error::outlives_its_keys);

    auto keys_newer_than_the_card = unsigned_card(bob, Keys{.spk = now + 200, .pqspk = now + 200, .ssk = now + 200});
    keys_newer_than_the_card.expires_at = now + 100;
    EXPECT_TRUE(checked(signed_as_is(bob, alice, keys_newer_than_the_card), alice).has_value());
}

TEST(Card, SigningFollowsTheProducerRule)
{
    const Producer bob;
    const auto alice = new_identity();
    EXPECT_EQ(signed_card(bob, alice, unsigned_card(bob)).expires_at, now + card_lifetime);
    const std::uint64_t five_days_ago = now - (5 * day);
    for (const auto& keys : {Keys{.spk = five_days_ago}, Keys{.pqspk = five_days_ago}, Keys{.ssk = five_days_ago}}) {
        const auto older = signed_card(bob, alice, unsigned_card(bob, keys));
        EXPECT_EQ(older.expires_at, five_days_ago + usable_for);
        EXPECT_TRUE(checked(older, alice).has_value());
    }

    EXPECT_EQ(test::error_of(sign_card(bob.identity, unsigned_card(bob, Keys{.ssk = now - usable_for}), signing_key_of(alice), now)),
        Error::outlives_its_keys);

    constexpr std::uint64_t late = std::numeric_limits<std::uint64_t>::max() - day;
    const auto at_the_end = sign_card(
        bob.identity, unsigned_card(bob, Keys{.spk = late, .pqspk = late, .ssk = late}), signing_key_of(alice), late);
    ASSERT_TRUE(at_the_end.has_value());
    EXPECT_EQ(at_the_end->expires_at, std::numeric_limits<std::uint64_t>::max());
}

TEST(Card, SignsOnlyWhatItsReceiverAccepts)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto refused = [&bob, &alice](const wire::Card& card) {
        return test::error_of(sign_card(bob.identity, card, signing_key_of(alice), now));
    };
    const Producer mallory;
    const auto stranger = identity::public_identity(mallory.identity);
    auto other_signing_key = unsigned_card(bob);
    other_signing_key.certificate.ik_sig = stranger.signing_key;
    EXPECT_EQ(refused(other_signing_key), Error::not_the_owner);
    auto other_exchange_key = unsigned_card(bob);
    other_exchange_key.certificate.ik_dh = stranger.exchange_key;
    EXPECT_EQ(refused(other_exchange_key), Error::not_the_owner);
    auto other_binding = unsigned_card(bob);
    other_binding.bind = stranger.binding;
    EXPECT_EQ(refused(other_binding), Error::not_the_owner);
    EXPECT_EQ(test::error_of(sign_card(mallory.identity, unsigned_card(bob), signing_key_of(alice), now)),
        Error::not_the_owner);

    auto wrong_kind = unsigned_card(bob);
    wrong_kind.pqspk.kind = wire::PrekeyKind::kem_one_time;
    EXPECT_EQ(refused(wrong_kind), Error::invalid_keys);
    auto forged_key = unsigned_card(bob);
    forged_key.ssk.key = crypto::x25519_generate().public_key;
    EXPECT_EQ(refused(forged_key), Error::invalid_keys);
    auto other_generation = unsigned_card(bob);
    other_generation.generation = 2;
    EXPECT_EQ(refused(other_generation), Error::invalid_keys);
    EXPECT_EQ(refused(unsigned_card(bob, Keys{.pqspk = now + skew + 1})), Error::invalid_keys);
    EXPECT_TRUE(sign_card(bob.identity, unsigned_card(bob, Keys{.pqspk = now + skew}), signing_key_of(alice), now)
                    .has_value());
}

TEST(Card, ChecksItsKeysLikeABundle)
{
    const Producer bob;
    const auto alice = new_identity();
    auto forged_key = unsigned_card(bob);
    forged_key.spk.key = crypto::x25519_generate().public_key;
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, forged_key), alice)), Error::invalid_keys);

    auto wrong_binding = unsigned_card(bob);
    wrong_binding.bind.front() = static_cast<std::uint8_t>(wrong_binding.bind.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, wrong_binding), alice)), Error::invalid_keys);

    auto other_generation = unsigned_card(bob);
    other_generation.generation = 2;
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, other_generation), alice)), Error::invalid_keys);

    const auto one_time_kem = unsigned_card(bob, Keys{.pq_kind = wire::PrekeyKind::kem_one_time});
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, one_time_kem), alice)), Error::invalid_keys);

    const crypto::ByteArray<crypto::x25519_key_size> unreduced{0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x7f};
    auto non_canonical = unsigned_card(bob);
    non_canonical.spk = must(handshake::make_prekey_x(bob.identity,
        handshake::PrekeyFacts{.kind = wire::PrekeyKind::signed_prekey, .id = 1, .created_at = now, .generation = 1},
        unreduced));
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, non_canonical), alice)), Error::invalid_keys);
    EXPECT_EQ(test::error_of(sign_card(bob.identity, non_canonical, signing_key_of(alice), now)), Error::invalid_keys);

    auto non_canonical_ssk = unsigned_card(bob);
    non_canonical_ssk.ssk = must(handshake::make_prekey_x(bob.identity,
        handshake::PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 3, .created_at = now, .generation = 1},
        unreduced));
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, non_canonical_ssk), alice)), Error::invalid_keys);

    auto from_the_future = unsigned_card(bob, Keys{.spk = now + skew + 1});
    from_the_future.expires_at = now + day;
    EXPECT_EQ(test::error_of(checked(signed_as_is(bob, alice, from_the_future), alice)), Error::invalid_keys);
}

TEST(Card, HoldsTheProducerToItsPin)
{
    const Producer bob;
    const auto alice = new_identity();
    const auto card = signed_card(bob, alice, unsigned_card(bob));
    const handshake::Pin same{.identity = identity::public_identity(bob.identity), .generation = 1};
    EXPECT_TRUE(checked(card, alice, same).has_value());

    const handshake::Pin someone_else{.identity = identity::public_identity(new_identity()), .generation = 1};
    EXPECT_EQ(test::error_of(checked(card, alice, someone_else)), Error::identity_changed);
    const handshake::Pin later{.identity = identity::public_identity(bob.identity), .generation = 2};
    EXPECT_EQ(test::error_of(checked(card, alice, later)), Error::generation_went_down);

    const auto recovered = signed_card(bob, alice, unsigned_card(bob, Keys{.generation = 2}));
    EXPECT_TRUE(checked(recovered, alice, same).has_value());
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
    const auto good = signed_card(bob, alice, unsigned_card(bob));
    const auto refused = [&recipient](const wire::Card& card) {
        return test::error_of(seal::seal_card(recipient, card, now));
    };
    auto unsigned_spk = good;
    unsigned_spk.spk.signature.reset();
    EXPECT_EQ(refused(unsigned_spk), seal::Error::malformed);
    auto unsigned_ssk = good;
    unsigned_ssk.ssk.signature.reset();
    EXPECT_EQ(refused(unsigned_ssk), seal::Error::malformed);
    auto seal_key_as_spk = good;
    seal_key_as_spk.spk.kind = wire::PrekeyKind::seal_key;
    EXPECT_EQ(refused(seal_key_as_spk), seal::Error::malformed);
    auto one_time_kem = good;
    one_time_kem.pqspk.kind = wire::PrekeyKind::kem_one_time;
    EXPECT_EQ(refused(one_time_kem), seal::Error::malformed);
    auto spk_as_ssk = good;
    spk_as_ssk.ssk.kind = wire::PrekeyKind::signed_prekey;
    EXPECT_EQ(refused(spk_as_ssk), seal::Error::malformed);
    auto long_name = good;
    long_name.certificate.username = std::string(wire::username_bound + 1, 'a');
    EXPECT_EQ(refused(long_name), seal::Error::malformed);
    auto name_with_nul = good;
    name_with_nul.certificate.username = std::string("bo\0b", 4);
    EXPECT_EQ(refused(name_with_nul), seal::Error::malformed);
    auto expired = good;
    expired.expires_at = now;
    EXPECT_EQ(refused(expired), seal::Error::malformed);
    auto longest = good;
    longest.expires_at = now + card_lifetime + skew;
    EXPECT_TRUE(seal::seal_card(recipient, longest, now).has_value());
    auto too_far_ahead = good;
    too_far_ahead.expires_at = now + card_lifetime + skew + 1;
    EXPECT_EQ(refused(too_far_ahead), seal::Error::malformed);

    auto sealed = must(seal::seal_card(recipient, good, now));
    EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id + 1, keys, sealed)), seal::Error::wrong_key);
    sealed.box.back() = static_cast<std::uint8_t>(sealed.box.back() ^ 0x01U);
    EXPECT_EQ(test::error_of(seal::open_card(recipient.seal_key.id, keys, sealed)), seal::Error::authentication_failed);
}

}
}
