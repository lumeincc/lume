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
#include <vector>

namespace lume::directory {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint64_t now = 1'800'003'600;
constexpr std::uint64_t today = now - (now % day);
constexpr std::uint64_t skew = handshake::allowed_clock_skew;

template <typename T, typename E>
T must(std::expected<T, E> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

template <typename E>
void must(const std::expected<void, E>& result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
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

Directory holding(const World& world, wire::DirectoryKeys list)
{
    Directory directory(world.root.public_key);
    must(directory.restore(signed_by(world.root, std::move(list))));
    return directory;
}

Error acceptance_of(const World& world, wire::DirectoryKeys list, std::uint64_t at = now)
{
    Directory directory(world.root.public_key);
    return test::error_of(directory.accept(signed_by(world.root, std::move(list)), at));
}

Result<void> checked(
    const World& world, const wire::UsernameCertificate& certificate, std::uint64_t at = now,
    const std::optional<wire::DirectoryKeys>& list = std::nullopt)
{
    const auto directory = holding(world, list.value_or(unsigned_list(world)));
    return directory.check_certificate(
        signed_by(world.directory, certificate), at, identity::public_identity(world.alice), world.account);
}

Error refusal_of(
    const World& world, const wire::UsernameCertificate& certificate, std::uint64_t at = now,
    const std::optional<wire::DirectoryKeys>& list = std::nullopt)
{
    return test::error_of(checked(world, certificate, at, list));
}

TEST(Directory, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/directory.json");
    const auto at = vectors.at("now").get<std::uint64_t>();
    const auto root = must(crypto::ed25519_from_seed(SecretBytes::copy_of(hex_field(vectors.at("root"), "seed"))));
    ASSERT_EQ(test::to_hex(root.public_key), vectors.at("root").at("public").get<std::string>());

    const auto& list_vector = vectors.at("list");
    const auto list = must(wire::decode(hex_field(list_vector, "encoded"), wire::read_directory_keys));
    EXPECT_EQ(list.sequence, list_vector.at("sequence").get<std::uint64_t>());
    EXPECT_EQ(list.issued_at, list_vector.at("issued_at").get<std::uint64_t>());
    EXPECT_EQ(list.expires_at, list_vector.at("expires_at").get<std::uint64_t>());
    const auto& key_vectors = vectors.at("directory_keys");
    ASSERT_EQ(list.keys.size(), key_vectors.size());
    for (std::size_t index = 0; index < list.keys.size(); ++index) {
        const auto& key = list.keys.at(index);
        const auto& expected = key_vectors.at(index);
        EXPECT_EQ(key.key_id, expected.at("key_id").get<std::uint32_t>()) << index;
        EXPECT_EQ(test::to_hex(key.public_key), expected.at("public").get<std::string>()) << index;
        EXPECT_EQ(key.not_before, expected.at("not_before").get<std::uint64_t>()) << index;
        EXPECT_EQ(key.not_after, expected.at("not_after").get<std::uint64_t>()) << index;
    }
    const auto& revoked_vectors = list_vector.at("revoked");
    ASSERT_EQ(list.revoked.size(), revoked_vectors.size());
    for (std::size_t index = 0; index < list.revoked.size(); ++index) {
        EXPECT_EQ(list.revoked.at(index).key_id, revoked_vectors.at(index).at("key_id").get<std::uint32_t>()) << index;
        EXPECT_EQ(list.revoked.at(index).since, revoked_vectors.at(index).at("since").get<std::uint64_t>()) << index;
    }
    EXPECT_EQ(test::to_hex(list.signature), list_vector.at("signature").get<std::string>());
    EXPECT_EQ(test::to_hex(list_message(list)), list_vector.at("message").get<std::string>());
    EXPECT_EQ(test::to_hex(must(crypto::ed25519_sign(root.seed, list_message(list)))),
        list_vector.at("signature").get<std::string>());
    EXPECT_EQ(test::to_hex(wire::encode(list)), list_vector.at("encoded").get<std::string>());

    Directory directory(root.public_key);
    ASSERT_TRUE(directory.accept(list, at).has_value());
    const auto revoked_id = revoked_vectors.at(0).at("key_id").get<std::uint32_t>();
    const auto since = revoked_vectors.at(0).at("since").get<std::uint64_t>();
    EXPECT_TRUE(directory.distrusts(revoked_id, since));
    EXPECT_FALSE(directory.distrusts(revoked_id, since - revocation_margin - 1));

    const auto& certificate_vector = vectors.at("certificate");
    const auto certificate =
        must(wire::decode(hex_field(certificate_vector, "encoded"), wire::read_username_certificate));
    EXPECT_EQ(certificate.key_id, certificate_vector.at("key_id").get<std::uint32_t>());
    EXPECT_EQ(certificate.username, certificate_vector.at("username").get<std::string>());
    EXPECT_EQ(test::to_hex(certificate.account_id), certificate_vector.at("account_id").get<std::string>());
    EXPECT_EQ(test::to_hex(certificate.ik_sig), certificate_vector.at("ik_sig").get<std::string>());
    EXPECT_EQ(test::to_hex(certificate.ik_dh), certificate_vector.at("ik_dh").get<std::string>());
    EXPECT_EQ(certificate.generation, certificate_vector.at("generation").get<std::uint32_t>());
    EXPECT_EQ(certificate.issued_at, certificate_vector.at("issued_at").get<std::uint64_t>());
    EXPECT_EQ(certificate.expires_at, certificate_vector.at("expires_at").get<std::uint64_t>());
    EXPECT_EQ(test::to_hex(certificate_message(certificate)), certificate_vector.at("message").get<std::string>());
    const auto signer =
        must(crypto::ed25519_from_seed(SecretBytes::copy_of(hex_field(key_vectors.at(0), "seed"))));
    EXPECT_EQ(test::to_hex(must(crypto::ed25519_sign(signer.seed, certificate_message(certificate)))),
        certificate_vector.at("signature").get<std::string>());

    const identity::PublicIdentity alice{
        .signing_key = certificate.ik_sig, .exchange_key = certificate.ik_dh, .binding = {}};
    EXPECT_TRUE(directory.check_certificate(certificate, at, alice, certificate.account_id).has_value());
}

TEST(Directory, AcceptsAFreshSignedList)
{
    const World world;
    Directory directory(world.root.public_key);
    EXPECT_FALSE(directory.current_at(now));
    ASSERT_TRUE(directory.accept(signed_by(world.root, unsigned_list(world)), now).has_value());
    EXPECT_TRUE(directory.current_at(now));
    ASSERT_TRUE(directory.list().has_value());
    EXPECT_EQ(directory.list().value_or(wire::DirectoryKeys{}).sequence, 7U);
}

TEST(Directory, RefusesAListNotSignedByTheRoot)
{
    const World world;
    Directory directory(world.root.public_key);
    auto forged = signed_by(world.root, unsigned_list(world));
    forged.signature.front() = static_cast<std::uint8_t>(forged.signature.front() ^ 0x01U);
    EXPECT_EQ(test::error_of(directory.accept(forged, now)), Error::invalid_signature);
    EXPECT_EQ(test::error_of(directory.accept(signed_by(world.directory, unsigned_list(world)), now)),
        Error::invalid_signature);
    auto changed_after_signing = signed_by(world.root, unsigned_list(world));
    changed_after_signing.sequence += 1;
    EXPECT_EQ(test::error_of(directory.accept(changed_after_signing, now)), Error::invalid_signature);
    EXPECT_EQ(test::error_of(directory.restore(forged)), Error::invalid_signature);
    EXPECT_FALSE(directory.list().has_value());
}

TEST(Directory, RefusesMalformedLists)
{
    const World world;
    auto duplicate_id = unsigned_list(world);
    duplicate_id.keys.push_back(duplicate_id.keys.front());
    duplicate_id.keys.back().public_key = crypto::ed25519_generate().public_key;
    EXPECT_EQ(acceptance_of(world, duplicate_id), Error::malformed);

    auto duplicate_public_key = unsigned_list(world);
    duplicate_public_key.keys.push_back(duplicate_public_key.keys.front());
    duplicate_public_key.keys.back().key_id = 2;
    EXPECT_EQ(acceptance_of(world, duplicate_public_key), Error::malformed);

    auto duplicate_revocation = unsigned_list(world);
    duplicate_revocation.revoked = {
        wire::RevokedKey{.key_id = 9, .since = today}, wire::RevokedKey{.key_id = 9, .since = today}};
    EXPECT_EQ(acceptance_of(world, duplicate_revocation), Error::malformed);

    auto listed_and_revoked = unsigned_list(world);
    listed_and_revoked.revoked = {wire::RevokedKey{.key_id = 1, .since = today}};
    EXPECT_EQ(acceptance_of(world, listed_and_revoked), Error::malformed);

    auto empty_window = unsigned_list(world);
    empty_window.keys.front().not_after = empty_window.keys.front().not_before;
    EXPECT_EQ(acceptance_of(world, empty_window), Error::malformed);

    auto too_many = unsigned_list(world);
    too_many.keys.resize(wire::directory_keys_bound + 1);
    Directory directory(world.root.public_key);
    EXPECT_EQ(test::error_of(directory.accept(too_many, now)), Error::malformed);
}

TEST(Directory, RefusesListsWithABadLifetime)
{
    const World world;
    auto longest = unsigned_list(world);
    longest.expires_at = longest.issued_at + list_lifetime;
    Directory directory(world.root.public_key);
    EXPECT_TRUE(directory.accept(signed_by(world.root, longest), now).has_value());

    auto too_long = unsigned_list(world);
    too_long.expires_at = too_long.issued_at + list_lifetime + 1;
    EXPECT_EQ(acceptance_of(world, too_long), Error::bad_lifetime);

    auto backwards = unsigned_list(world);
    backwards.expires_at = backwards.issued_at;
    EXPECT_EQ(acceptance_of(world, backwards), Error::bad_lifetime);
}

TEST(Directory, RefusesListsOutsideTheirTime)
{
    const World world;
    auto issued_soon = unsigned_list(world);
    issued_soon.issued_at = now + skew;
    issued_soon.expires_at = issued_soon.issued_at + day;
    Directory directory(world.root.public_key);
    EXPECT_TRUE(directory.accept(signed_by(world.root, issued_soon), now).has_value());

    auto issued_later = unsigned_list(world);
    issued_later.issued_at = now + skew + 1;
    issued_later.expires_at = issued_later.issued_at + day;
    EXPECT_EQ(acceptance_of(world, issued_later), Error::not_yet_valid);

    auto expires_now = unsigned_list(world);
    expires_now.expires_at = now;
    EXPECT_EQ(acceptance_of(world, expires_now), Error::expired);

    auto expires_next = unsigned_list(world);
    expires_next.expires_at = now + 1;
    Directory other(world.root.public_key);
    EXPECT_TRUE(other.accept(signed_by(world.root, expires_next), now).has_value());
}

TEST(Directory, NeverGoesBackToAnOlderList)
{
    const World world;
    auto directory = holding(world, unsigned_list(world));
    const auto offer = [&world, &directory](wire::DirectoryKeys list) {
        return directory.accept(signed_by(world.root, std::move(list)), now);
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
    EXPECT_EQ(test::error_of(offer(unsigned_list(world))), Error::rolled_back);
}

TEST(Directory, AReplayedOlderListCannotRestoreARevokedKey)
{
    const World world;
    auto directory = holding(world, unsigned_list(world));
    const auto certificate = signed_by(world.directory, unsigned_certificate(world));
    const auto alice = identity::public_identity(world.alice);
    ASSERT_TRUE(directory.check_certificate(certificate, now, alice, world.account).has_value());

    auto revoking = unsigned_list(world);
    revoking.sequence = 8;
    revoking.keys.clear();
    revoking.revoked = {wire::RevokedKey{.key_id = 1, .since = today - day}};
    ASSERT_TRUE(directory.accept(signed_by(world.root, revoking), now).has_value());
    EXPECT_EQ(test::error_of(directory.check_certificate(certificate, now, alice, world.account)), Error::unknown_key);

    const auto replay = signed_by(world.root, unsigned_list(world));
    EXPECT_EQ(test::error_of(directory.accept(replay, now)), Error::rolled_back);
    EXPECT_EQ(test::error_of(directory.restore(replay)), Error::rolled_back);
    EXPECT_EQ(test::error_of(directory.check_certificate(certificate, now, alice, world.account)), Error::unknown_key);
    EXPECT_TRUE(directory.distrusts(1, today));
}

TEST(Directory, NeverReusesAKeyId)
{
    const World world;
    auto directory = holding(world, unsigned_list(world));
    auto other_key_same_id = unsigned_list(world);
    other_key_same_id.sequence = 8;
    other_key_same_id.keys.front().public_key = crypto::ed25519_generate().public_key;
    EXPECT_EQ(test::error_of(directory.accept(signed_by(world.root, other_key_same_id), now)), Error::conflicting_list);

    auto revoking = unsigned_list(world);
    revoking.sequence = 8;
    revoking.keys.front().key_id = 2;
    revoking.keys.front().public_key = crypto::ed25519_generate().public_key;
    revoking.revoked = {wire::RevokedKey{.key_id = 1, .since = today}};
    ASSERT_TRUE(directory.accept(signed_by(world.root, revoking), now).has_value());

    auto relisted = unsigned_list(world);
    relisted.sequence = 9;
    EXPECT_EQ(test::error_of(directory.accept(signed_by(world.root, relisted), now)), Error::conflicting_list);
}

TEST(Directory, AStoredListSetsTheFloorEvenWhenExpired)
{
    const World world;
    auto shipped = unsigned_list(world);
    shipped.sequence = 20;
    shipped.issued_at = today - (30 * day);
    shipped.expires_at = today - (20 * day);
    auto directory = holding(world, shipped);
    EXPECT_FALSE(directory.current_at(now));
    EXPECT_EQ(test::error_of(directory.check_certificate(signed_by(world.directory, unsigned_certificate(world)), now,
                  identity::public_identity(world.alice), world.account)),
        Error::no_current_list);
    EXPECT_EQ(test::error_of(directory.accept(signed_by(world.root, unsigned_list(world)), now)), Error::rolled_back);

    auto newer = unsigned_list(world);
    newer.sequence = 21;
    EXPECT_TRUE(directory.accept(signed_by(world.root, newer), now).has_value());
    EXPECT_TRUE(directory.current_at(now));
}

TEST(Directory, AcceptsACertificateItCanVerify)
{
    const World world;
    EXPECT_TRUE(checked(world, unsigned_certificate(world)).has_value());
}

TEST(Directory, RefusesCertificatesWithoutACurrentList)
{
    const World world;
    const Directory empty(world.root.public_key);
    EXPECT_EQ(test::error_of(empty.check_certificate(signed_by(world.directory, unsigned_certificate(world)), now,
                  identity::public_identity(world.alice), world.account)),
        Error::no_current_list);
    EXPECT_FALSE(empty.distrusts(1, now));

    EXPECT_EQ(refusal_of(world, unsigned_certificate(world), today + (13 * day)), Error::no_current_list);
    EXPECT_TRUE(checked(world, unsigned_certificate(world), today + (13 * day) - 1).has_value());

    auto issued_later = unsigned_list(world);
    issued_later.issued_at = now + skew + 1;
    issued_later.expires_at = issued_later.issued_at + day;
    EXPECT_EQ(refusal_of(world, unsigned_certificate(world), now, issued_later), Error::no_current_list);
}

TEST(Directory, RefusesCertificatesFromKeysItCannotUse)
{
    const World world;
    const auto certificate = unsigned_certificate(world);
    auto unknown = certificate;
    unknown.key_id = 2;
    EXPECT_EQ(refusal_of(world, unknown), Error::unknown_key);

    auto starts_within_skew = unsigned_list(world);
    starts_within_skew.keys.front().not_before = now + skew;
    EXPECT_TRUE(checked(world, certificate, now, starts_within_skew).has_value());
    auto starts_later = unsigned_list(world);
    starts_later.keys.front().not_before = now + skew + 1;
    EXPECT_EQ(refusal_of(world, certificate, now, starts_later), Error::key_outside_window);

    auto ends_next = unsigned_list(world);
    ends_next.keys.front().not_after = now + 1;
    EXPECT_TRUE(checked(world, certificate, now, ends_next).has_value());
    auto ends_now = unsigned_list(world);
    ends_now.keys.front().not_after = now;
    EXPECT_EQ(refusal_of(world, certificate, now, ends_now), Error::key_outside_window);

    auto revoked = unsigned_list(world);
    revoked.keys.clear();
    revoked.revoked = {wire::RevokedKey{.key_id = 1, .since = today - day}};
    EXPECT_EQ(refusal_of(world, certificate, now, revoked), Error::unknown_key);
}

TEST(Directory, RefusesUsernamesOutsideTheRule)
{
    const World world;
    for (const auto& name : std::vector<std::string>{"abc", "a_1", "user_2026", std::string(wire::username_bound, 'z')}) {
        auto certificate = unsigned_certificate(world);
        certificate.username = name;
        EXPECT_TRUE(checked(world, certificate).has_value()) << name;
    }
    const std::string right_to_left_override{static_cast<char>(0xE2), static_cast<char>(0x80), static_cast<char>(0xAE)};
    for (const auto& name :
         std::vector<std::string>{"ab", "ALICE", "Alice", "ali ce", "ali-ce", "\xD0\xB0lice", right_to_left_override + "ecila"}) {
        auto certificate = unsigned_certificate(world);
        certificate.username = name;
        EXPECT_EQ(refusal_of(world, certificate), Error::invalid_username) << name;
    }
    auto too_long = unsigned_certificate(world);
    too_long.username = std::string(wire::username_bound + 1, 'a');
    const auto directory = holding(world, unsigned_list(world));
    EXPECT_EQ(test::error_of(directory.check_certificate(
                  too_long, now, identity::public_identity(world.alice), world.account)),
        Error::invalid_username);
}

TEST(Directory, RefusesACertificateWithABadSignature)
{
    const World world;
    const auto directory = holding(world, unsigned_list(world));
    const auto alice = identity::public_identity(world.alice);
    auto forged = signed_by(world.directory, unsigned_certificate(world));
    forged.username = "mallory";
    EXPECT_EQ(test::error_of(directory.check_certificate(forged, now, alice, world.account)), Error::invalid_signature);
    const auto by_root = signed_by(world.root, unsigned_certificate(world));
    EXPECT_EQ(test::error_of(directory.check_certificate(by_root, now, alice, world.account)), Error::invalid_signature);
}

TEST(Directory, RefusesCertificatesOutsideTheirTime)
{
    const World world;
    auto issued_soon = unsigned_certificate(world);
    issued_soon.issued_at = now + skew;
    issued_soon.expires_at = issued_soon.issued_at + certificate_lifetime;
    EXPECT_TRUE(checked(world, issued_soon).has_value());

    auto issued_later = unsigned_certificate(world);
    issued_later.issued_at = now + skew + 1;
    issued_later.expires_at = issued_later.issued_at + day;
    EXPECT_EQ(refusal_of(world, issued_later), Error::not_yet_valid);

    auto expires_now = unsigned_certificate(world);
    expires_now.expires_at = now;
    EXPECT_EQ(refusal_of(world, expires_now), Error::expired);
    auto expires_next = unsigned_certificate(world);
    expires_next.expires_at = now + 1;
    EXPECT_TRUE(checked(world, expires_next).has_value());

    auto longest = unsigned_certificate(world);
    longest.expires_at = longest.issued_at + certificate_lifetime;
    EXPECT_TRUE(checked(world, longest).has_value());
    auto too_long = unsigned_certificate(world);
    too_long.expires_at = too_long.issued_at + certificate_lifetime + 1;
    EXPECT_EQ(refusal_of(world, too_long), Error::bad_lifetime);

    auto backwards = unsigned_certificate(world);
    backwards.issued_at = now + skew;
    backwards.expires_at = now + 1;
    EXPECT_EQ(refusal_of(world, backwards), Error::bad_lifetime);
}

TEST(Directory, RefusesACertificateForSomeoneElse)
{
    const World world;
    const auto directory = holding(world, unsigned_list(world));
    const auto certificate = signed_by(world.directory, unsigned_certificate(world));
    const auto stranger =
        identity::public_identity(must(identity::derive_identity(crypto::random_secret(identity::entropy_size))));
    EXPECT_EQ(test::error_of(directory.check_certificate(certificate, now, stranger, world.account)),
        Error::wrong_identity);

    auto other_exchange_key = identity::public_identity(world.alice);
    other_exchange_key.exchange_key = stranger.exchange_key;
    EXPECT_EQ(test::error_of(directory.check_certificate(certificate, now, other_exchange_key, world.account)),
        Error::wrong_identity);

    EXPECT_EQ(test::error_of(directory.check_certificate(certificate, now, identity::public_identity(world.alice),
                  crypto::random_public_bytes<wire::account_id_size>())),
        Error::wrong_account);
}

TEST(Directory, DistrustsNamesAcceptedAfterARevocationLessADay)
{
    const World world;
    auto list = unsigned_list(world);
    const std::uint64_t since = today - (2 * day);
    list.revoked = {wire::RevokedKey{.key_id = 5, .since = since}};
    const auto directory = holding(world, list);
    EXPECT_TRUE(directory.distrusts(5, since + 10));
    EXPECT_TRUE(directory.distrusts(5, since));
    EXPECT_TRUE(directory.distrusts(5, since - revocation_margin));
    EXPECT_FALSE(directory.distrusts(5, since - revocation_margin - 1));
    EXPECT_FALSE(directory.distrusts(1, since));
}

RC_GTEST_PROP(DirectoryProperties, AnyChangedBitOfASignedListIsRefused, ())
{
    const World world;
    const auto encoded = wire::encode(signed_by(world.root, unsigned_list(world)));
    const auto changed = wire::decode(test::flip_random_bit(encoded), wire::read_directory_keys);
    if (changed) {
        Directory directory(world.root.public_key);
        RC_ASSERT_FALSE(directory.accept(*changed, now).has_value());
    }
}

}
}
