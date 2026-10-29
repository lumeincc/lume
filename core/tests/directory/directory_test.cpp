// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/directory/directory.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/random.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/identity.hpp"
#include "lume/identity/phrase.hpp"
#include "support/expected.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::directory {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint64_t now = 1'800'003'600;
constexpr std::uint64_t today = now - (now % day);

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

struct World {
    crypto::Ed25519KeyPair root = crypto::ed25519_generate();
    crypto::Ed25519KeyPair directory = crypto::ed25519_generate();
    identity::Identity alice = must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
    crypto::ByteArray<wire::account_id_size> account = crypto::random_public_bytes<wire::account_id_size>();
};

wire::DirectoryKeys signed_by(const crypto::Ed25519KeyPair& signer, wire::DirectoryKeys list)
{
    list.signature = must(crypto::ed25519_sign(signer.seed, list_message(list)));
    return list;
}

wire::UsernameCertificate signed_by(const crypto::Ed25519KeyPair& signer, wire::UsernameCertificate certificate)
{
    certificate.signature = must(crypto::ed25519_sign(signer.seed, certificate_message(certificate)));
    return certificate;
}

wire::DirectoryKeys unsigned_list(const World& world)
{
    wire::DirectoryKeys list;
    list.sequence = 7;
    list.issued_at = today - day;
    list.expires_at = today + (13 * day);
    list.keys.push_back(wire::DirectoryKey{
        .key_id = 1, .public_key = world.directory.public_key, .not_before = today - (7 * day),
        .not_after = today + (60 * day)});
    return list;
}

wire::UsernameCertificate unsigned_certificate(const World& world)
{
    const auto alice = identity::public_identity(world.alice);
    wire::UsernameCertificate certificate;
    certificate.key_id = 1;
    certificate.username = "alice";
    certificate.account_id = world.account;
    certificate.ik_sig = alice.signing_key;
    certificate.ik_dh = alice.exchange_key;
    certificate.generation = 1;
    certificate.issued_at = today;
    certificate.expires_at = today + (30 * day);
    return certificate;
}

TrustedList trusted(const World& world, wire::DirectoryKeys list)
{
    return must(TrustedList::verify(world.root.public_key, signed_by(world.root, std::move(list))));
}

Error refusal_of(const World& world, wire::DirectoryKeys list, std::uint64_t at = now)
{
    return test::error_of(accept_list(world.root.public_key, signed_by(world.root, std::move(list)), at, std::nullopt));
}

Error refusal_of(
    const World& world, const wire::UsernameCertificate& certificate, std::uint64_t at = now,
    const std::optional<wire::DirectoryKeys>& list = std::nullopt)
{
    const auto held = trusted(world, list.value_or(unsigned_list(world)));
    return test::error_of(check_certificate(
        held, signed_by(world.directory, certificate), at, identity::public_identity(world.alice), world.account));
}

bool accepts(const World& world, const wire::UsernameCertificate& certificate, std::uint64_t at = now)
{
    const auto held = trusted(world, unsigned_list(world));
    return check_certificate(
               held, signed_by(world.directory, certificate), at, identity::public_identity(world.alice), world.account)
        .has_value();
}

TEST(Directory, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/directory.json");
    const auto at = vectors.at("now").get<std::uint64_t>();
    const auto root_seed = SecretBytes::copy_of(hex_field(vectors.at("root"), "seed"));
    const auto root = must(crypto::ed25519_from_seed(SecretBytes::copy_of(root_seed.view())));
    ASSERT_EQ(test::to_hex(root.public_key), vectors.at("root").at("public").get<std::string>());

    const auto& list_vector = vectors.at("list");
    const auto list = must(wire::decode(hex_field(list_vector, "encoded"), wire::read_directory_keys));
    EXPECT_EQ(list.sequence, list_vector.at("sequence").get<std::uint64_t>());
    EXPECT_EQ(list.keys.size(), vectors.at("directory_keys").size());
    EXPECT_EQ(test::to_hex(list_message(list)), list_vector.at("message").get<std::string>());
    EXPECT_EQ(test::to_hex(must(crypto::ed25519_sign(root.seed, list_message(list)))),
        list_vector.at("signature").get<std::string>());
    EXPECT_EQ(test::to_hex(wire::encode(list)), list_vector.at("encoded").get<std::string>());
    const auto accepted = accept_list(root.public_key, list, at, std::nullopt);
    ASSERT_TRUE(accepted.has_value());

    const auto& certificate_vector = vectors.at("certificate");
    const auto certificate =
        must(wire::decode(hex_field(certificate_vector, "encoded"), wire::read_username_certificate));
    EXPECT_EQ(certificate.username, certificate_vector.at("username").get<std::string>());
    EXPECT_EQ(test::to_hex(certificate_message(certificate)), certificate_vector.at("message").get<std::string>());
    const auto& signer_vector = vectors.at("directory_keys").at(0);
    const auto signer = must(crypto::ed25519_from_seed(SecretBytes::copy_of(hex_field(signer_vector, "seed"))));
    EXPECT_EQ(test::to_hex(must(crypto::ed25519_sign(signer.seed, certificate_message(certificate)))),
        certificate_vector.at("signature").get<std::string>());

    const identity::PublicIdentity alice{
        .signing_key = array_of<wire::ed25519_key_size>(hex_field(certificate_vector, "ik_sig")),
        .exchange_key = array_of<wire::x25519_key_size>(hex_field(certificate_vector, "ik_dh")),
        .binding = {}};
    const auto account = array_of<wire::account_id_size>(hex_field(certificate_vector, "account_id"));
    EXPECT_TRUE(check_certificate(*accepted, certificate, at, alice, account).has_value());
}

TEST(Directory, AcceptsAFreshSignedList)
{
    const World world;
    const auto accepted =
        accept_list(world.root.public_key, signed_by(world.root, unsigned_list(world)), now, std::nullopt);
    ASSERT_TRUE(accepted.has_value());
    EXPECT_TRUE(accepted->current_at(now));
    EXPECT_EQ(accepted->keys().sequence, 7U);
}

TEST(Directory, RefusesAListNotSignedByTheRoot)
{
    const World world;
    auto forged = signed_by(world.root, unsigned_list(world));
    forged.signature.front() = static_cast<std::uint8_t>(forged.signature.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(accept_list(world.root.public_key, forged, now, std::nullopt)), Error::invalid_signature);

    const auto by_other_key = signed_by(world.directory, unsigned_list(world));
    EXPECT_EQ(
        test::error_of(accept_list(world.root.public_key, by_other_key, now, std::nullopt)), Error::invalid_signature);

    auto changed_after_signing = signed_by(world.root, unsigned_list(world));
    changed_after_signing.sequence += 1;
    EXPECT_EQ(test::error_of(accept_list(world.root.public_key, changed_after_signing, now, std::nullopt)),
        Error::invalid_signature);
}

TEST(Directory, RefusesMalformedLists)
{
    const World world;
    auto duplicate_key = unsigned_list(world);
    duplicate_key.keys.push_back(duplicate_key.keys.front());
    EXPECT_EQ(refusal_of(world, duplicate_key), Error::malformed);

    auto duplicate_revocation = unsigned_list(world);
    duplicate_revocation.revoked = {wire::RevokedKey{.key_id = 9, .since = today}, wire::RevokedKey{.key_id = 9, .since = today}};
    EXPECT_EQ(refusal_of(world, duplicate_revocation), Error::malformed);

    auto listed_and_revoked = unsigned_list(world);
    listed_and_revoked.revoked = {wire::RevokedKey{.key_id = 1, .since = today}};
    EXPECT_EQ(refusal_of(world, listed_and_revoked), Error::malformed);

    auto empty_window = unsigned_list(world);
    empty_window.keys.front().not_after = empty_window.keys.front().not_before;
    EXPECT_EQ(refusal_of(world, empty_window), Error::malformed);
}

TEST(Directory, RefusesListsThatLiveTooLong)
{
    const World world;
    auto longest = unsigned_list(world);
    longest.expires_at = longest.issued_at + list_lifetime;
    EXPECT_TRUE(accept_list(world.root.public_key, signed_by(world.root, longest), now, std::nullopt).has_value());

    auto too_long = unsigned_list(world);
    too_long.expires_at = too_long.issued_at + list_lifetime + 1;
    EXPECT_EQ(refusal_of(world, too_long), Error::lifetime_too_long);

    auto backwards = unsigned_list(world);
    backwards.expires_at = backwards.issued_at;
    EXPECT_EQ(refusal_of(world, backwards), Error::lifetime_too_long);
}

TEST(Directory, RefusesListsOutsideTheirTime)
{
    const World world;
    auto issued_soon = unsigned_list(world);
    issued_soon.issued_at = now + handshake::allowed_clock_skew;
    issued_soon.expires_at = issued_soon.issued_at + day;
    EXPECT_TRUE(accept_list(world.root.public_key, signed_by(world.root, issued_soon), now, std::nullopt).has_value());

    auto issued_later = unsigned_list(world);
    issued_later.issued_at = now + handshake::allowed_clock_skew + 1;
    issued_later.expires_at = issued_later.issued_at + day;
    EXPECT_EQ(refusal_of(world, issued_later), Error::not_yet_valid);

    auto expired = unsigned_list(world);
    expired.expires_at = now;
    EXPECT_EQ(refusal_of(world, expired), Error::expired);
}

TEST(Directory, NeverGoesBackToAnOlderList)
{
    const World world;
    const std::optional<TrustedList> held = trusted(world, unsigned_list(world));
    const auto offer = [&world, &held](wire::DirectoryKeys list) {
        return accept_list(world.root.public_key, signed_by(world.root, std::move(list)), now, held);
    };

    auto older = unsigned_list(world);
    older.sequence = 6;
    EXPECT_EQ(test::error_of(offer(older)), Error::rolled_back);
    EXPECT_TRUE(offer(unsigned_list(world)).has_value());

    auto same_sequence_other_content = unsigned_list(world);
    same_sequence_other_content.expires_at -= day;
    EXPECT_EQ(test::error_of(offer(same_sequence_other_content)), Error::conflicting_list);

    auto newer = unsigned_list(world);
    newer.sequence = 8;
    EXPECT_TRUE(offer(newer).has_value());
}

TEST(Directory, AnExpiredListStillSetsTheSequenceFloor)
{
    const World world;
    auto shipped = unsigned_list(world);
    shipped.sequence = 20;
    shipped.issued_at = today - (30 * day);
    shipped.expires_at = today - (20 * day);
    const auto floor = TrustedList::verify(world.root.public_key, signed_by(world.root, shipped));
    ASSERT_TRUE(floor.has_value());
    EXPECT_FALSE(floor->current_at(now));

    const std::optional<TrustedList> held = *floor;
    EXPECT_EQ(test::error_of(accept_list(world.root.public_key, signed_by(world.root, unsigned_list(world)), now, held)),
        Error::rolled_back);
}

TEST(Directory, AcceptsACertificateItCanVerify)
{
    const World world;
    const auto list = trusted(world, unsigned_list(world));
    const auto certificate = signed_by(world.directory, unsigned_certificate(world));
    EXPECT_TRUE(
        check_certificate(list, certificate, now, identity::public_identity(world.alice), world.account).has_value());
}

TEST(Directory, RefusesCertificatesFromKeysItCannotUse)
{
    const World world;
    const auto certificate = unsigned_certificate(world);
    EXPECT_EQ(refusal_of(world, certificate, today + (13 * day)), Error::list_expired);

    auto unknown = certificate;
    unknown.key_id = 2;
    EXPECT_EQ(refusal_of(world, unknown), Error::unknown_key);

    auto not_yet = unsigned_list(world);
    not_yet.keys.front().not_before = now + 1;
    EXPECT_EQ(refusal_of(world, certificate, now, not_yet), Error::key_outside_window);
    auto retired = unsigned_list(world);
    retired.keys.front().not_after = now - 1;
    EXPECT_EQ(refusal_of(world, certificate, now, retired), Error::key_outside_window);

    auto revoked = unsigned_list(world);
    revoked.keys.clear();
    revoked.revoked = {wire::RevokedKey{.key_id = 1, .since = today - day}};
    EXPECT_EQ(refusal_of(world, certificate, now, revoked), Error::unknown_key);
}

TEST(Directory, RefusesACertificateWithABadSignature)
{
    const World world;
    const auto list = trusted(world, unsigned_list(world));
    auto forged = signed_by(world.directory, unsigned_certificate(world));
    forged.username = "mallory";
    EXPECT_EQ(test::error_of(check_certificate(list, forged, now, identity::public_identity(world.alice), world.account)),
        Error::invalid_signature);
    const auto by_root = signed_by(world.root, unsigned_certificate(world));
    EXPECT_EQ(test::error_of(check_certificate(list, by_root, now, identity::public_identity(world.alice), world.account)),
        Error::invalid_signature);
}

TEST(Directory, RefusesCertificatesOutsideTheirTime)
{
    const World world;
    auto issued_soon = unsigned_certificate(world);
    issued_soon.issued_at = now + handshake::allowed_clock_skew;
    issued_soon.expires_at = issued_soon.issued_at + day;
    EXPECT_TRUE(accepts(world, issued_soon));

    auto issued_later = unsigned_certificate(world);
    issued_later.issued_at = now + handshake::allowed_clock_skew + 1;
    issued_later.expires_at = issued_later.issued_at + day;
    EXPECT_EQ(refusal_of(world, issued_later), Error::not_yet_valid);

    auto expired = unsigned_certificate(world);
    expired.expires_at = now;
    EXPECT_EQ(refusal_of(world, expired), Error::expired);

    auto longest = unsigned_certificate(world);
    longest.expires_at = longest.issued_at + certificate_lifetime;
    EXPECT_TRUE(accepts(world, longest));

    auto too_long = unsigned_certificate(world);
    too_long.expires_at = too_long.issued_at + certificate_lifetime + 1;
    EXPECT_EQ(refusal_of(world, too_long), Error::lifetime_too_long);

    auto backwards = unsigned_certificate(world);
    backwards.issued_at = now - 10;
    backwards.expires_at = now - 20;
    EXPECT_EQ(refusal_of(world, backwards), Error::expired);
}

TEST(Directory, RefusesACertificateForSomeoneElse)
{
    const World world;
    const auto list = trusted(world, unsigned_list(world));
    const auto certificate = signed_by(world.directory, unsigned_certificate(world));
    const auto stranger =
        identity::public_identity(must(identity::derive_identity(crypto::random_secret(identity::entropy_size))));
    EXPECT_EQ(test::error_of(check_certificate(list, certificate, now, stranger, world.account)), Error::wrong_identity);

    auto other_exchange_key = identity::public_identity(world.alice);
    other_exchange_key.exchange_key = stranger.exchange_key;
    EXPECT_EQ(test::error_of(check_certificate(list, certificate, now, other_exchange_key, world.account)),
        Error::wrong_identity);

    const auto other_account = crypto::random_public_bytes<wire::account_id_size>();
    EXPECT_EQ(
        test::error_of(check_certificate(list, certificate, now, identity::public_identity(world.alice), other_account)),
        Error::wrong_account);
}

TEST(Directory, DistrustsNamesAcceptedAfterARevocationLessADay)
{
    const World world;
    auto list = unsigned_list(world);
    const std::uint64_t since = today - (2 * day);
    list.revoked = {wire::RevokedKey{.key_id = 5, .since = since}};
    const auto held = trusted(world, list);
    EXPECT_TRUE(distrusts(held, 5, since + 10));
    EXPECT_TRUE(distrusts(held, 5, since));
    EXPECT_TRUE(distrusts(held, 5, since - revocation_margin));
    EXPECT_FALSE(distrusts(held, 5, since - revocation_margin - 1));
    EXPECT_FALSE(distrusts(held, 1, since));
}

RC_GTEST_PROP(DirectoryProperties, AnyChangedBitOfASignedListIsRefused, ())
{
    const World world;
    const auto encoded = wire::encode(signed_by(world.root, unsigned_list(world)));
    const auto changed = wire::decode(test::flip_random_bit(encoded), wire::read_directory_keys);
    if (changed) {
        RC_ASSERT_FALSE(accept_list(world.root.public_key, *changed, now, std::nullopt).has_value());
    }
}

}
}
