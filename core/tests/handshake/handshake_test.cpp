// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/handshake/handshake.hpp"

#include "lume/handshake/prekey.hpp"
#include "lume/identity/phrase.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::handshake {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint64_t created_at = 1'800'000'000;
constexpr std::uint64_t now = created_at + 3600;

template <typename T>
T must(crypto::Result<T> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

Bytes field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

std::string signature_hex(const wire::PrekeyX& prekey)
{
    return prekey.signature ? test::to_hex(*prekey.signature) : std::string();
}

identity::Identity identity_from(const Bytes& entropy)
{
    return must(identity::derive_identity(SecretBytes::copy_of(entropy)));
}

struct Responder {
    identity::Identity identity;
    std::uint32_t generation = identity::first_generation;
    crypto::X25519KeyPair signed_prekey;
    crypto::MlKemKeyPair kem_prekey;
    wire::PrekeyKind kem_kind = wire::PrekeyKind::kem_last_resort;
    crypto::X25519KeyPair seal_key;
    std::optional<crypto::X25519KeyPair> one_time_prekey;
};

PrekeyFacts facts(wire::PrekeyKind kind, std::uint32_t id, std::uint64_t at, std::uint32_t generation)
{
    return PrekeyFacts{.kind = kind, .id = id, .created_at = at, .generation = generation};
}

Bundle bundle_of(const Responder& responder, std::uint64_t at)
{
    const auto& owner = responder.identity;
    const auto generation = responder.generation;
    Bundle published{
        .identity = identity::public_identity(owner),
        .generation = generation,
        .signed_prekey = must(make_prekey_x(
            owner, facts(wire::PrekeyKind::signed_prekey, 11, at, generation), responder.signed_prekey.public_key)),
        .kem_prekey = must(
            make_prekey_kem(owner, facts(responder.kem_kind, 22, at, generation), responder.kem_prekey.public_key)),
        .seal_key = must(
            make_prekey_x(owner, facts(wire::PrekeyKind::seal_key, 33, at, generation), responder.seal_key.public_key)),
        .one_time_prekey = std::nullopt};
    if (responder.one_time_prekey) {
        published.one_time_prekey = must(make_prekey_x(
            owner, facts(wire::PrekeyKind::one_time_prekey, 44, at, generation), responder.one_time_prekey->public_key));
    }
    return published;
}

ResponderKeys keys_of(const Responder& responder)
{
    const auto& one_time = responder.one_time_prekey;
    return ResponderKeys{
        .signed_prekey_id = 11,
        .signed_prekey = std::cref(responder.signed_prekey),
        .kem_kind = responder.kem_kind,
        .kem_id = 22,
        .kem_prekey = std::cref(responder.kem_prekey),
        .one_time_prekey_id = one_time ? std::optional<std::uint32_t>(44) : std::nullopt,
        .one_time_prekey = one_time ? std::optional(std::cref(*one_time)) : std::nullopt};
}

Responder random_responder(bool with_one_time_prekey)
{
    Responder responder{
        .identity = identity_from(test::random_bytes_of(identity::entropy_size)),
        .generation = *rc::gen::inRange<std::uint32_t>(1, 5),
        .signed_prekey = crypto::x25519_generate(),
        .kem_prekey = crypto::mlkem768_generate(),
        .kem_kind = *rc::gen::element(wire::PrekeyKind::kem_last_resort, wire::PrekeyKind::kem_one_time),
        .seal_key = crypto::x25519_generate(),
        .one_time_prekey = std::nullopt};
    if (with_one_time_prekey) {
        responder.one_time_prekey = crypto::x25519_generate();
    }
    return responder;
}

Responder fixed_responder()
{
    return Responder{
        .identity = identity_from(Bytes(identity::entropy_size, 0x42)),
        .generation = 1,
        .signed_prekey = crypto::x25519_generate(),
        .kem_prekey = crypto::mlkem768_generate(),
        .kem_kind = wire::PrekeyKind::kem_last_resort,
        .seal_key = crypto::x25519_generate(),
        .one_time_prekey = crypto::x25519_generate()};
}

template <std::size_t Size>
void flip_first_bit(crypto::ByteArray<Size>& bytes)
{
    bytes.front() = static_cast<std::uint8_t>(bytes.front() ^ 1U);
}

void expect_same_keys(const SessionKeys& left, const SessionKeys& right)
{
    EXPECT_TRUE(left.root_key.equals(right.root_key.view()));
    EXPECT_TRUE(left.header_key_alice.equals(right.header_key_alice.view()));
    EXPECT_TRUE(left.next_header_key_bob.equals(right.next_header_key_bob.view()));
    EXPECT_EQ(left.associated_data, right.associated_data);
}

TEST(Handshake, MatchesTheLumeVectors)
{
    const auto identities = test::load_vectors("lume/identity.json").at("cases");
    const auto kem_suite = test::load_wycheproof("mlkem_768_test.json");
    const auto cases = test::load_vectors("lume/handshake.json").at("cases");
    ASSERT_EQ(cases.size(), 2U);
    for (const auto& vector : cases) {
        const auto alice = identity_from(field(identities.at(vector.at("alice").get<std::size_t>()), "entropy"));
        const auto bob = identity_from(field(identities.at(vector.at("bob").get<std::size_t>()), "entropy"));
        const auto generation = vector.at("generation").get<std::uint32_t>();
        const auto at = vector.at("created_at").get<std::uint64_t>();

        nlohmann::json kem_case;
        const auto tc_id = vector.at("kem_prekey").at("wycheproof_tcId").get<int>();
        test::for_each_wycheproof_case(kem_suite, [&](const test::WycheproofCase& wycheproof) {
            if (wycheproof.id() == tc_id) {
                kem_case = wycheproof.test;
            }
        });
        ASSERT_FALSE(kem_case.is_null());

        const auto& spk_vector = vector.at("signed_prekey");
        const auto spk = must(crypto::x25519_from_secret(SecretBytes::copy_of(field(spk_vector, "secret"))));
        const auto& ssk_vector = vector.at("seal_key");
        const auto ssk = must(crypto::x25519_from_secret(SecretBytes::copy_of(field(ssk_vector, "secret"))));
        const auto kem = must(crypto::mlkem768_from_seed(SecretBytes::copy_of(field(kem_case, "seed"))));
        ASSERT_EQ(kem.public_key, field(kem_case, "ek"));
        const auto kem_kind = static_cast<wire::PrekeyKind>(vector.at("kem_prekey").at("kind").get<int>());

        Bundle bundle{
            .identity = identity::public_identity(bob),
            .generation = generation,
            .signed_prekey = must(make_prekey_x(
                bob, PrekeyFacts{.kind = wire::PrekeyKind::signed_prekey, .id = spk_vector.at("id").get<std::uint32_t>(), .created_at = at, .generation = generation},
                spk.public_key)),
            .kem_prekey = must(make_prekey_kem(
                bob, PrekeyFacts{.kind = kem_kind, .id = vector.at("kem_prekey").at("id").get<std::uint32_t>(), .created_at = at, .generation = generation},
                kem.public_key)),
            .seal_key = must(make_prekey_x(
                bob, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = ssk_vector.at("id").get<std::uint32_t>(), .created_at = at, .generation = generation},
                ssk.public_key)),
            .one_time_prekey = std::nullopt};
        EXPECT_EQ(signature_hex(bundle.signed_prekey), spk_vector.at("signature").get<std::string>());
        EXPECT_EQ(test::to_hex(bundle.kem_prekey.signature), vector.at("kem_prekey").at("signature").get<std::string>());
        EXPECT_EQ(signature_hex(bundle.seal_key), ssk_vector.at("signature").get<std::string>());

        std::optional<crypto::X25519KeyPair> one_time;
        if (!vector.at("one_time_prekey").is_null()) {
            const auto& opk_vector = vector.at("one_time_prekey");
            one_time = must(crypto::x25519_from_secret(SecretBytes::copy_of(field(opk_vector, "secret"))));
            bundle.one_time_prekey = must(make_prekey_x(
                bob,
                PrekeyFacts{.kind = wire::PrekeyKind::one_time_prekey, .id = opk_vector.at("id").get<std::uint32_t>(), .created_at = at, .generation = generation},
                one_time->public_key));
        }

        const crypto::MlKemEncapsulation encapsulation{
            .ciphertext = field(kem_case, "c"), .shared_secret = SecretBytes::copy_of(field(kem_case, "K"))};
        const auto initiation = detail::initiate_with(
            alice, bundle, std::nullopt, vector.at("now").get<std::uint64_t>(),
            SecretBytes::copy_of(field(vector, "ephemeral_secret")), encapsulation);
        ASSERT_TRUE(initiation.has_value());
        EXPECT_TRUE(initiation->keys.root_key.equals(field(vector, "root_key")));
        EXPECT_TRUE(initiation->keys.header_key_alice.equals(field(vector, "header_key_alice")));
        EXPECT_TRUE(initiation->keys.next_header_key_bob.equals(field(vector, "next_header_key_bob")));
        EXPECT_EQ(initiation->keys.associated_data, field(vector, "associated_data"));
        EXPECT_EQ(wire::encode(initiation->header), field(vector, "initial_header"));
        EXPECT_EQ(test::to_hex(replay_tag(initiation->header)), vector.at("replay_tag").get<std::string>());
        EXPECT_EQ(initiation->peer_ratchet_key, spk.public_key);

        const ResponderKeys keys{
            .signed_prekey_id = bundle.signed_prekey.id,
            .signed_prekey = std::cref(spk),
            .kem_kind = kem_kind,
            .kem_id = bundle.kem_prekey.id,
            .kem_prekey = std::cref(kem),
            .one_time_prekey_id = initiation->header.opk_id,
            .one_time_prekey = one_time ? std::optional(std::cref(*one_time)) : std::nullopt};
        const auto response = respond(bob, initiation->header, keys);
        ASSERT_TRUE(response.has_value());
        expect_same_keys(*response, initiation->keys);
    }
}

TEST(Handshake, RefusesABundleThatDoesNotCheckOut)
{
    const auto alice = identity_from(Bytes(identity::entropy_size, 0x41));
    const auto bob = fixed_responder();
    const auto good = bundle_of(bob, created_at);
    ASSERT_TRUE(check_bundle(good, std::nullopt, now).has_value());

    auto bad_binding = good;
    flip_first_bit(bad_binding.identity.binding);
    EXPECT_EQ(check_bundle(bad_binding, std::nullopt, now).error(), Error::invalid_binding);

    EXPECT_EQ(check_bundle(good, identity::public_identity(alice), now).error(), Error::identity_changed);
    EXPECT_TRUE(check_bundle(good, identity::public_identity(bob.identity), now).has_value());

    auto wrong_generation = good;
    wrong_generation.generation = good.generation + 1;
    EXPECT_EQ(check_bundle(wrong_generation, std::nullopt, now).error(), Error::invalid_prekey);

    auto forged_spk = good;
    flip_first_bit(forged_spk.signed_prekey.key);
    EXPECT_EQ(check_bundle(forged_spk, std::nullopt, now).error(), Error::invalid_prekey);

    auto forged_kem = good;
    flip_first_bit(forged_kem.kem_prekey.key);
    EXPECT_EQ(check_bundle(forged_kem, std::nullopt, now).error(), Error::invalid_prekey);

    auto swapped = good;
    std::swap(swapped.signed_prekey, swapped.seal_key);
    EXPECT_EQ(check_bundle(swapped, std::nullopt, now).error(), Error::invalid_prekey);

    auto signed_one_time = good;
    ASSERT_TRUE(signed_one_time.one_time_prekey.has_value());
    if (signed_one_time.one_time_prekey) {
        signed_one_time.one_time_prekey->signature = good.signed_prekey.signature;
    }
    EXPECT_EQ(check_bundle(signed_one_time, std::nullopt, now).error(), Error::invalid_prekey);
}

TEST(Handshake, RefusesKeysOutsideTheirWindow)
{
    const auto bob = fixed_responder();
    const auto bundle = bundle_of(bob, created_at);
    EXPECT_TRUE(check_bundle(bundle, std::nullopt, created_at - allowed_clock_skew).has_value());
    EXPECT_EQ(check_bundle(bundle, std::nullopt, created_at - allowed_clock_skew - 1).error(), Error::prekey_not_usable);
    EXPECT_TRUE(check_bundle(bundle, std::nullopt, created_at + rotating_key_usable_for).has_value());
    EXPECT_EQ(check_bundle(bundle, std::nullopt, created_at + rotating_key_usable_for + 1).error(), Error::prekey_not_usable);
}

TEST(Handshake, AOneTimeKemKeyHasNoAgeLimit)
{
    auto bob = fixed_responder();
    bob.kem_kind = wire::PrekeyKind::kem_one_time;
    auto bundle = bundle_of(bob, created_at);
    const auto later = created_at + (100 * rotating_key_usable_for);
    bundle.signed_prekey = must(make_prekey_x(
        bob.identity, PrekeyFacts{.kind = wire::PrekeyKind::signed_prekey, .id = 11, .created_at = later, .generation = 1},
        bob.signed_prekey.public_key));
    bundle.seal_key = must(make_prekey_x(
        bob.identity, PrekeyFacts{.kind = wire::PrekeyKind::seal_key, .id = 33, .created_at = later, .generation = 1},
        bob.seal_key.public_key));
    EXPECT_TRUE(check_bundle(bundle, std::nullopt, later).has_value());
}

TEST(Handshake, RefusesALowOrderSignedPrekey)
{
    const auto alice = identity_from(Bytes(identity::entropy_size, 0x41));
    const auto bob = fixed_responder();
    auto bundle = bundle_of(bob, created_at);
    const Bytes low_order(crypto::x25519_key_size, 0);
    bundle.signed_prekey = must(make_prekey_x(
        bob.identity, PrekeyFacts{.kind = wire::PrekeyKind::signed_prekey, .id = 11, .created_at = created_at, .generation = 1},
        low_order));
    EXPECT_EQ(initiate(alice, bundle, std::nullopt, now).error(), Error::weak_key);
}

TEST(Handshake, AnEphemeralKeyHasOneEncoding)
{
    const auto alice = identity_from(Bytes(identity::entropy_size, 0x41));
    const auto bob = fixed_responder();
    const auto initiation = initiate(alice, bundle_of(bob, created_at), std::nullopt, now);
    ASSERT_TRUE(initiation.has_value());
    ASSERT_TRUE(respond(bob.identity, initiation->header, keys_of(bob)).has_value());

    auto top_bit = initiation->header;
    top_bit.ephemeral_key.back() = static_cast<std::uint8_t>(top_bit.ephemeral_key.back() | 0x80U);
    EXPECT_NE(replay_tag(top_bit), replay_tag(initiation->header));
    EXPECT_EQ(initiator_of(top_bit, std::nullopt).error(), Error::non_canonical_key);
    EXPECT_EQ(respond(bob.identity, top_bit, keys_of(bob)).error(), Error::non_canonical_key);

    auto above_prime = initiation->header;
    above_prime.ephemeral_key.fill(0xff);
    above_prime.ephemeral_key.back() = 0x7f;
    EXPECT_EQ(respond(bob.identity, above_prime, keys_of(bob)).error(), Error::non_canonical_key);
}

TEST(Handshake, RefusesANonCanonicalBundleKey)
{
    const auto alice = identity_from(Bytes(identity::entropy_size, 0x41));
    const auto bob = fixed_responder();
    auto bundle = bundle_of(bob, created_at);
    auto key = bob.signed_prekey.public_key;
    key.back() = static_cast<std::uint8_t>(key.back() | 0x80U);
    bundle.signed_prekey = must(make_prekey_x(
        bob.identity, PrekeyFacts{.kind = wire::PrekeyKind::signed_prekey, .id = 11, .created_at = created_at, .generation = 1},
        key));
    EXPECT_EQ(check_bundle(bundle, std::nullopt, now).error(), Error::non_canonical_key);
    EXPECT_EQ(initiate(alice, bundle, std::nullopt, now).error(), Error::non_canonical_key);
}

TEST(Handshake, ResponderRefusesKeysThatDoNotMatchTheHeader)
{
    const auto alice = identity_from(Bytes(identity::entropy_size, 0x41));
    const auto bob = fixed_responder();
    const auto initiation = initiate(alice, bundle_of(bob, created_at), std::nullopt, now);
    ASSERT_TRUE(initiation.has_value());

    auto keys = keys_of(bob);
    keys.signed_prekey_id += 1;
    EXPECT_EQ(respond(bob.identity, initiation->header, keys).error(), Error::unknown_prekey);

    keys = keys_of(bob);
    keys.one_time_prekey.reset();
    keys.one_time_prekey_id.reset();
    EXPECT_EQ(respond(bob.identity, initiation->header, keys).error(), Error::unknown_prekey);

    keys = keys_of(bob);
    keys.kem_kind = wire::PrekeyKind::kem_one_time;
    EXPECT_EQ(respond(bob.identity, initiation->header, keys).error(), Error::unknown_prekey);

    auto forged = initiation->header;
    flip_first_bit(forged.bind);
    EXPECT_EQ(respond(bob.identity, forged, keys_of(bob)).error(), Error::invalid_binding);
    EXPECT_EQ(initiator_of(forged, std::nullopt).error(), Error::invalid_binding);
    EXPECT_EQ(
        initiator_of(initiation->header, identity::public_identity(bob.identity)).error(), Error::identity_changed);
    EXPECT_TRUE(initiator_of(initiation->header, identity::public_identity(alice)).has_value());
}

RC_GTEST_PROP(HandshakeProperties, BothSidesDeriveTheSameKeys, (bool with_one_time_prekey))
{
    const auto alice = identity_from(test::random_bytes_of(identity::entropy_size));
    const auto bob = random_responder(with_one_time_prekey);
    const auto initiation = initiate(alice, bundle_of(bob, created_at), std::nullopt, now);
    RC_ASSERT(initiation.has_value());
    RC_ASSERT(initiation->header.opk_id.has_value() == with_one_time_prekey);
    const auto response = respond(bob.identity, initiation->header, keys_of(bob));
    RC_ASSERT(response.has_value());
    RC_ASSERT(response->root_key.equals(initiation->keys.root_key.view()));
    RC_ASSERT(response->header_key_alice.equals(initiation->keys.header_key_alice.view()));
    RC_ASSERT(response->next_header_key_bob.equals(initiation->keys.next_header_key_bob.view()));
    RC_ASSERT(response->associated_data == initiation->keys.associated_data);
}

RC_GTEST_PROP(HandshakeProperties, EveryHandshakeHasFreshKeys, ())
{
    const auto alice = identity_from(test::random_bytes_of(identity::entropy_size));
    const auto bob = random_responder(false);
    const auto bundle = bundle_of(bob, created_at);
    const auto first = initiate(alice, bundle, std::nullopt, now);
    const auto second = initiate(alice, bundle, std::nullopt, now);
    RC_ASSERT(first.has_value() && second.has_value());
    RC_ASSERT_FALSE(first->keys.root_key.equals(second->keys.root_key.view()));
    RC_ASSERT(first->header.ephemeral_key != second->header.ephemeral_key);
    RC_ASSERT(replay_tag(first->header) != replay_tag(second->header));
}

RC_GTEST_PROP(HandshakeProperties, ATamperedKeyMaterialFieldGivesDifferentKeys, ())
{
    const auto alice = identity_from(test::random_bytes_of(identity::entropy_size));
    const auto bob = random_responder(true);
    const auto initiation = initiate(alice, bundle_of(bob, created_at), std::nullopt, now);
    RC_ASSERT(initiation.has_value());
    auto forged = initiation->header;
    if (*rc::gen::arbitrary<bool>()) {
        const auto flipped = test::flip_random_bit(forged.ephemeral_key);
        std::ranges::copy(flipped, forged.ephemeral_key.begin());
    } else {
        const auto flipped = test::flip_random_bit(forged.kem_ciphertext);
        std::ranges::copy(flipped, forged.kem_ciphertext.begin());
    }
    const auto response = respond(bob.identity, forged, keys_of(bob));
    if (response) {
        RC_ASSERT_FALSE(response->root_key.equals(initiation->keys.root_key.view()));
    } else {
        RC_ASSERT(response.error() == Error::weak_key || response.error() == Error::non_canonical_key);
    }
}

}
}
