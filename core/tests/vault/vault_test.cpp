// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/vault/keys.hpp"
#include "lume/vault/records.hpp"

#include "lume/crypto/random.hpp"
#include "support/expected.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"
#include "vault/vault_internal.hpp"

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

namespace lume::vault {
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

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

SecretBytes secret_field(const nlohmann::json& object, const char* name)
{
    return SecretBytes::copy_of(hex_field(object, name));
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

std::string text_of(const Bytes& bytes)
{
    return {bytes.begin(), bytes.end()};
}

Error error_named(const std::string& name)
{
    if (name == "wrong_passphrase") {
        return Error::wrong_passphrase;
    }
    if (name == "integrity") {
        return Error::integrity;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

const nlohmann::json& vectors()
{
    static const auto loaded = test::load_vectors("lume/vault.json");
    return loaded;
}

Keys vector_keys()
{
    return must(keys_of(secret_field(vectors().at("keys"), "data_key")));
}

RecordAddress address_of(const nlohmann::json& vector)
{
    return RecordAddress{
        .type = vector.at("type").get<std::uint8_t>(),
        .id = hex_field(vector, "id"),
        .counter = std::stoull(vector.at("counter").get<std::string>())};
}

TpmPoint tpm_point()
{
    TpmPoint point{};
    point.front() = wire::tpm_point_uncompressed;
    return point;
}

Protection protection_for(wire::HardwareMode mode)
{
    return Protection{
        .salt = fresh_salt(),
        .cost = cost_floor,
        .hw_mode = mode,
        .tpm_point = mode == wire::HardwareMode::tpm ? std::optional<TpmPoint>(tpm_point()) : std::nullopt,
        .epoch = 3};
}

TEST(VaultKeys, MatchTheLumeVectors)
{
    const auto& keys = vectors().at("keys");
    const auto& floor = vectors().at("argon2id").at(0);
    ASSERT_EQ(floor.at("name").get<std::string>(), "floor");
    const auto passphrase_key = derive_passphrase_key(text_of(hex_field(floor, "passphrase")),
        array_of<wire::vault_salt_size>(hex_field(keys, "salt")),
        Cost{.ops = keys.at("ops").get<std::uint32_t>(), .mem = keys.at("mem").get<std::uint32_t>()});
    ASSERT_TRUE(passphrase_key.has_value());
    EXPECT_EQ(test::to_hex(passphrase_key->view()), keys.at("passphrase_key").get<std::string>());

    const auto& keystore = keys.at("keystore");
    const auto keystore_master = derive_master_key(*passphrase_key, secret_field(keystore, "hardware_key"));
    ASSERT_TRUE(keystore_master.has_value());
    EXPECT_EQ(test::to_hex(keystore_master->view()), keystore.at("master_key").get<std::string>());

    const auto& tpm = keys.at("tpm");
    const auto authorisation = derive_tpm_authorisation(*passphrase_key);
    ASSERT_TRUE(authorisation.has_value());
    EXPECT_EQ(test::to_hex(authorisation->view()), tpm.at("authorisation").get<std::string>());
    const auto hardware_key = derive_tpm_hardware_key(secret_field(tpm, "shared_secret"));
    ASSERT_TRUE(hardware_key.has_value());
    EXPECT_EQ(test::to_hex(hardware_key->view()), tpm.at("hardware_key").get<std::string>());
    const auto tpm_master = derive_master_key(*passphrase_key, *hardware_key);
    ASSERT_TRUE(tpm_master.has_value());
    EXPECT_EQ(test::to_hex(tpm_master->view()), tpm.at("master_key").get<std::string>());

    const auto derived = vector_keys();
    EXPECT_EQ(test::to_hex(derived.record.view()), keys.at("record_key").get<std::string>());
    EXPECT_EQ(test::to_hex(derived.manifest.view()), keys.at("manifest_key").get<std::string>());
    EXPECT_EQ(test::to_hex(derived.root.view()), keys.at("root_key").get<std::string>());
}

TEST(VaultHeader, MatchesTheLumeVectors)
{
    const auto& keys = vectors().at("keys");
    const auto data = vector_keys();
    int checked = 0;
    for (const auto& vector : vectors().at("headers")) {
        const auto name = vector.at("name").get<std::string>();
        const auto master_key = secret_field(vector, "master_key");
        std::optional<TpmPoint> point;
        if (!vector.at("tpm_point").is_null()) {
            point = array_of<wire::tpm_point_size>(hex_field(vector, "tpm_point"));
            EXPECT_EQ(vector.at("tpm_point").get<std::string>(), keys.at("tpm").at("point").get<std::string>());
        }
        const Protection protection{
            .salt = array_of<wire::vault_salt_size>(hex_field(keys, "salt")),
            .cost = Cost{.ops = keys.at("ops").get<std::uint32_t>(), .mem = keys.at("mem").get<std::uint32_t>()},
            .hw_mode = static_cast<wire::HardwareMode>(vector.at("hw_mode").get<std::uint8_t>()),
            .tpm_point = point,
            .epoch = vector.at("epoch").get<std::uint64_t>()};
        const auto sealed = detail::seal_header(
            master_key, data, protection, array_of<crypto::aead_nonce_size>(hex_field(vector, "nonce")));
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(test::to_hex(sealed->wrapped_data_key), vector.at("wrapped_data_key").get<std::string>()) << name;
        EXPECT_EQ(test::to_hex(sealed->check), vector.at("check").get<std::string>()) << name;
        EXPECT_EQ(test::to_hex(wire::encode(*sealed)), vector.at("encoded").get<std::string>()) << name;

        const auto decoded = wire::decode(hex_field(vector, "encoded"), wire::read_vault_header);
        ASSERT_TRUE(decoded.has_value()) << name;
        const auto opened = open_header(master_key, *decoded);
        ASSERT_TRUE(opened.has_value()) << name;
        EXPECT_TRUE(opened->data.equals(data.data.view())) << name;
        EXPECT_TRUE(opened->record.equals(data.record.view())) << name;
        ++checked;
    }
    EXPECT_EQ(checked, 2);

    int refused = 0;
    for (const auto& refusal : vectors().at("header_refusals")) {
        const auto name = refusal.at("name").get<std::string>();
        const auto decoded = wire::decode(hex_field(refusal, "encoded"), wire::read_vault_header);
        ASSERT_TRUE(decoded.has_value()) << name;
        EXPECT_EQ(test::error_of(open_header(secret_field(refusal, "master_key"), *decoded)),
            error_named(refusal.at("error").get<std::string>()))
            << name;
        ++refused;
    }
    EXPECT_EQ(refused, 6);
}

TEST(VaultRecords, MatchTheLumeVectors)
{
    const auto keys = vector_keys();
    int checked = 0;
    for (const auto& vector : vectors().at("records")) {
        const auto name = vector.at("name").get<std::string>();
        const auto address = address_of(vector);
        const auto payload = hex_field(vector, "payload");
        const auto sealed =
            detail::seal_record(keys, address, payload, array_of<crypto::aead_nonce_size>(hex_field(vector, "nonce")));
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(test::to_hex(*sealed), vector.at("record").get<std::string>()) << name;
        const auto opened = open_record(keys, address, hex_field(vector, "record"));
        ASSERT_TRUE(opened.has_value()) << name;
        EXPECT_TRUE(opened->equals(payload)) << name;
        const auto term = root_term(keys, address, hex_field(vector, "record"));
        ASSERT_TRUE(term.has_value()) << name;
        EXPECT_EQ(test::to_hex(*term), vector.at("root_term").get<std::string>()) << name;
        ++checked;
    }
    EXPECT_EQ(checked, 4);

    const auto& earlier = vectors().at("earlier_write");
    const auto& current = vectors().at("records").at(0);
    const auto address = address_of(current);
    const auto earlier_payload = open_record(keys, address, hex_field(earlier, "record"));
    ASSERT_TRUE(earlier_payload.has_value());
    EXPECT_TRUE(earlier_payload->equals(hex_field(earlier, "payload")));
    const auto earlier_term = root_term(keys, address, hex_field(earlier, "record"));
    ASSERT_TRUE(earlier_term.has_value());
    EXPECT_EQ(test::to_hex(*earlier_term), earlier.at("root_term").get<std::string>());
    EXPECT_NE(test::to_hex(*earlier_term), current.at("root_term").get<std::string>());

    int refused = 0;
    for (const auto& refusal : vectors().at("record_refusals")) {
        EXPECT_EQ(test::error_of(open_record(keys, address_of(refusal), hex_field(refusal, "record"))),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 4);
}

TEST(VaultRoots, MatchTheLumeVectors)
{
    const auto& roots = vectors().at("roots");
    Root type_one{};
    Root type_two{};
    for (const auto& vector : vectors().at("records")) {
        const auto term = array_of<wire::manifest_root_size>(hex_field(vector, "root_term"));
        auto& root = vector.at("type").get<int>() == 1 ? type_one : type_two;
        root = add_term(root, term);
    }
    EXPECT_EQ(test::to_hex(type_one), roots.at("type_1").get<std::string>());
    EXPECT_EQ(test::to_hex(type_two), roots.at("type_2").get<std::string>());

    const auto& update = roots.at("update");
    const auto before = array_of<wire::manifest_root_size>(hex_field(update, "before"));
    const auto after = add_term(remove_term(before, array_of<wire::manifest_root_size>(hex_field(update, "removed_term"))),
        array_of<wire::manifest_root_size>(hex_field(update, "added_term")));
    EXPECT_EQ(test::to_hex(after), update.at("after").get<std::string>());

    const auto& from_zero = roots.at("from_zero");
    EXPECT_EQ(test::to_hex(remove_term(Root{}, array_of<wire::manifest_root_size>(hex_field(from_zero, "term")))),
        from_zero.at("after").get<std::string>());
}

TEST(VaultManifest, MatchesTheLumeVectors)
{
    const auto keys = vector_keys();
    const auto& vector = vectors().at("manifest");
    const auto manifest = wire::decode(hex_field(vector, "encoded"), wire::read_manifest);
    ASSERT_TRUE(manifest.has_value());
    EXPECT_EQ(manifest->epoch, vector.at("epoch").get<std::uint64_t>());
    ASSERT_EQ(manifest->types.size(), 2U);
    EXPECT_EQ(test::to_hex(manifest->types.at(1).root), vectors().at("roots").at("type_2").get<std::string>());
    const auto tag = manifest_tag(keys, *manifest);
    ASSERT_TRUE(tag.has_value());
    EXPECT_EQ(test::to_hex(*tag), vector.at("tag").get<std::string>());
    EXPECT_TRUE(check_manifest(keys, *manifest, hex_field(vector, "tag"), manifest->epoch).has_value());

    int refused = 0;
    for (const auto& refusal : vector.at("refusals")) {
        const auto refused_manifest = wire::decode(hex_field(refusal, "encoded"), wire::read_manifest);
        ASSERT_TRUE(refused_manifest.has_value());
        EXPECT_EQ(test::error_of(check_manifest(
                      keys, *refused_manifest, hex_field(vector, "tag"), refusal.at("epoch").get<std::uint64_t>())),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 2);
}

TEST(VaultKeys, RefuseCostsOutsideTheirBounds)
{
    EXPECT_TRUE(within_bounds(cost_floor));
    EXPECT_TRUE(within_bounds(cost_ceiling));
    EXPECT_TRUE(within_bounds(android_cost));
    EXPECT_TRUE(within_bounds(desktop_cost));
    const Salt salt{};
    for (const auto cost : {Cost{.ops = cost_floor.ops - 1, .mem = cost_floor.mem},
             Cost{.ops = cost_ceiling.ops + 1, .mem = cost_floor.mem},
             Cost{.ops = cost_floor.ops, .mem = cost_floor.mem - 1},
             Cost{.ops = cost_floor.ops, .mem = cost_ceiling.mem + 1}}) {
        EXPECT_FALSE(within_bounds(cost));
        EXPECT_EQ(test::error_of(derive_passphrase_key("passphrase", salt, cost)), Error::integrity);
    }
    EXPECT_EQ(test::error_of(derive_passphrase_key(std::string(passphrase_bound + 1, 'a'), salt, cost_floor)),
        Error::invalid_passphrase);
}

TEST(VaultKeys, RefuseAHostileCostBeforeArgon2idRuns)
{
    const Salt salt{};
    for (const auto cost : {Cost{.ops = 0xffffffffU, .mem = cost_floor.mem}, Cost{.ops = cost_floor.ops, .mem = 0xffffffffU}}) {
        EXPECT_EQ(test::error_of(derive_passphrase_key("passphrase", salt, cost)), Error::integrity);
    }
    const auto longest = derive_passphrase_key(std::string(passphrase_bound, 'a'), salt, cost_floor);
    ASSERT_TRUE(longest.has_value());
    EXPECT_EQ(longest->size(), key_size);
}

TEST(VaultKeys, CheckNewPassphrases)
{
    using wire::HardwareMode;
    EXPECT_EQ(test::error_of(check_new_passphrase("123456789", HardwareMode::keystore)), Error::passphrase_too_short);
    EXPECT_TRUE(check_new_passphrase("1234567890", HardwareMode::keystore).has_value());
    EXPECT_TRUE(check_new_passphrase("1234567890", HardwareMode::tpm).has_value());
    EXPECT_EQ(test::error_of(check_new_passphrase("1234567890123", HardwareMode::software)), Error::passphrase_too_short);
    EXPECT_TRUE(check_new_passphrase("12345678901234", HardwareMode::software).has_value());
    EXPECT_TRUE(check_new_passphrase("пароль на день", HardwareMode::keystore).has_value());
    EXPECT_EQ(test::error_of(check_new_passphrase("пароль", HardwareMode::keystore)), Error::passphrase_too_short);
    const std::string five_emoji(std::size_t{5} * 4, '\xf0');
    std::string emoji;
    for (int count = 0; count < 5; ++count) {
        emoji += "\xf0\x9f\x94\x92";
    }
    EXPECT_EQ(emoji.size(), five_emoji.size());
    EXPECT_EQ(test::error_of(check_new_passphrase(emoji, HardwareMode::keystore)), Error::passphrase_too_short);
    EXPECT_EQ(test::error_of(check_new_passphrase(five_emoji, HardwareMode::keystore)), Error::invalid_passphrase);
    EXPECT_EQ(test::error_of(check_new_passphrase(std::string("12345\0" "67890", 11), HardwareMode::keystore)),
        Error::invalid_passphrase);
    EXPECT_EQ(test::error_of(check_new_passphrase("1234567890\xc0\xaf", HardwareMode::keystore)), Error::invalid_passphrase);
    EXPECT_TRUE(check_new_passphrase(std::string(passphrase_bound, 'a'), HardwareMode::software).has_value());
    EXPECT_EQ(test::error_of(check_new_passphrase(std::string(passphrase_bound + 1, 'a'), HardwareMode::software)),
        Error::invalid_passphrase);
}

TEST(VaultKeys, RefuseKeysOfTheWrongSize)
{
    const auto key = crypto::random_secret(key_size);
    const auto short_key = crypto::random_secret(key_size - 1);
    EXPECT_TRUE(derive_master_key(key, key).has_value());
    EXPECT_EQ(test::error_of(derive_master_key(short_key, key)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(derive_master_key(key, short_key)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(derive_tpm_authorisation(short_key)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(derive_tpm_hardware_key(short_key)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(keys_of(crypto::random_secret(key_size + 1))), Error::invalid_parameters);
    const auto master = derive_master_key(key, key);
    ASSERT_TRUE(master.has_value());
    EXPECT_FALSE(master->equals(must(derive_master_key(key, crypto::random_secret(key_size))).view()));
}

TEST(VaultHeader, OpensOnlyUnderItsMasterKeyInEveryMode)
{
    const auto keys = must(fresh_keys());
    const auto master = crypto::random_secret(key_size);
    for (const auto mode : {wire::HardwareMode::keystore, wire::HardwareMode::tpm, wire::HardwareMode::software}) {
        const auto header = seal_header(master, keys, protection_for(mode));
        ASSERT_TRUE(header.has_value());
        EXPECT_EQ(header->hw_mode, mode);
        EXPECT_EQ(header->epoch, 3U);
        const auto decoded = wire::decode(wire::encode(*header), wire::read_vault_header);
        ASSERT_TRUE(decoded.has_value());
        const auto opened = open_header(master, *decoded);
        ASSERT_TRUE(opened.has_value());
        EXPECT_TRUE(opened->data.equals(keys.data.view()));
        EXPECT_TRUE(opened->manifest.equals(keys.manifest.view()));
        EXPECT_TRUE(opened->root.equals(keys.root.view()));

        EXPECT_EQ(test::error_of(open_header(crypto::random_secret(key_size), *decoded)), Error::wrong_passphrase);
        auto flipped = *decoded;
        flipped.check.front() = static_cast<std::uint8_t>(flipped.check.front() ^ 0x01U);
        EXPECT_EQ(test::error_of(open_header(master, flipped)), Error::integrity);
        EXPECT_EQ(test::error_of(open_header(crypto::random_secret(key_size), flipped)), Error::wrong_passphrase);
        auto later = *decoded;
        later.epoch += 1;
        EXPECT_EQ(test::error_of(open_header(master, later)), Error::integrity);
        auto other_salt = *decoded;
        other_salt.salt.front() = static_cast<std::uint8_t>(other_salt.salt.front() ^ 0x01U);
        EXPECT_EQ(test::error_of(open_header(master, other_salt)), Error::integrity);
        auto broken_key = *decoded;
        broken_key.wrapped_data_key.back() = static_cast<std::uint8_t>(broken_key.wrapped_data_key.back() ^ 0x01U);
        EXPECT_EQ(test::error_of(open_header(master, broken_key)), Error::wrong_passphrase);
        auto cheaper = *decoded;
        cheaper.ops = cost_floor.ops - 1;
        EXPECT_EQ(test::error_of(open_header(master, cheaper)), Error::integrity);
    }
    const auto first = must(seal_header(master, keys, protection_for(wire::HardwareMode::keystore)));
    const auto second = must(seal_header(master, keys, protection_for(wire::HardwareMode::keystore)));
    EXPECT_NE(first.wrapped_data_key, second.wrapped_data_key);
    EXPECT_NE(first.salt, second.salt);
}

TEST(VaultHeader, RefusesProtectionItCannotWrite)
{
    const auto keys = must(fresh_keys());
    const auto master = crypto::random_secret(key_size);
    auto too_cheap = protection_for(wire::HardwareMode::keystore);
    too_cheap.cost.mem = cost_floor.mem - 1;
    EXPECT_EQ(test::error_of(seal_header(master, keys, too_cheap)), Error::invalid_parameters);
    auto tpm_without_point = protection_for(wire::HardwareMode::tpm);
    tpm_without_point.tpm_point.reset();
    EXPECT_EQ(test::error_of(seal_header(master, keys, tpm_without_point)), Error::invalid_parameters);
    auto point_without_tpm = protection_for(wire::HardwareMode::software);
    point_without_tpm.tpm_point = tpm_point();
    EXPECT_EQ(test::error_of(seal_header(master, keys, point_without_tpm)), Error::invalid_parameters);
    auto compressed = protection_for(wire::HardwareMode::tpm);
    auto compressed_point = tpm_point();
    compressed_point.front() = 0x02;
    compressed.tpm_point = compressed_point;
    EXPECT_EQ(test::error_of(seal_header(master, keys, compressed)), Error::invalid_parameters);
    auto unknown = protection_for(wire::HardwareMode::software);
    unknown.hw_mode = static_cast<wire::HardwareMode>(0);
    EXPECT_EQ(test::error_of(seal_header(master, keys, unknown)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(seal_header(crypto::random_secret(key_size - 1), keys, protection_for(wire::HardwareMode::software))),
        Error::invalid_parameters);
    EXPECT_EQ(test::error_of(seal_header(master, Keys{}, protection_for(wire::HardwareMode::software))),
        Error::invalid_parameters);

    auto header = must(seal_header(master, keys, protection_for(wire::HardwareMode::tpm)));
    header.tpm_point.reset();
    EXPECT_EQ(test::error_of(open_header(master, header)), Error::integrity);
}

TEST(VaultRecords, HoldWhatFitsAndOpenOnlyAtTheirAddress)
{
    const auto keys = must(fresh_keys());
    const RecordAddress address{.type = 4, .id = Bytes(record_id_bound, 9), .counter = 12};
    const Bytes largest(crypto::aead_max_plaintext_size, 3);
    const auto record = seal_record(keys, address, largest);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->size(), crypto::aead_overhead + largest.size());
    const auto opened = open_record(keys, address, *record);
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->equals(largest));
    EXPECT_EQ(test::error_of(seal_record(keys, address, Bytes(crypto::aead_max_plaintext_size + 1))),
        Error::record_too_large);

    auto newer = address;
    newer.counter += 1;
    EXPECT_EQ(test::error_of(open_record(keys, newer, *record)), Error::integrity);
    EXPECT_EQ(test::error_of(open_record(must(fresh_keys()), address, *record)), Error::integrity);
    EXPECT_EQ(test::error_of(open_record(keys, address, crypto::ByteView(*record).first(crypto::aead_overhead - 1))),
        Error::integrity);

    auto long_id = address;
    long_id.id.push_back(0);
    EXPECT_EQ(test::error_of(seal_record(keys, long_id, Bytes{1})), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(open_record(keys, long_id, *record)), Error::integrity);
    EXPECT_EQ(test::error_of(root_term(keys, long_id, *record)), Error::integrity);
    EXPECT_EQ(test::error_of(root_term(keys, address, crypto::ByteView(*record).first(crypto::aead_overhead - 1))),
        Error::integrity);
    EXPECT_TRUE(root_term(keys, address, crypto::ByteView(*record).first(crypto::aead_overhead)).has_value());
    EXPECT_EQ(test::error_of(seal_record(Keys{}, address, Bytes{1})), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(open_record(Keys{}, address, *record)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(root_term(Keys{}, address, *record)), Error::invalid_parameters);

    const auto term = must(root_term(keys, address, *record));
    EXPECT_NE(term, must(root_term(keys, newer, *record)));
    EXPECT_NE(term, must(root_term(must(fresh_keys()), address, *record)));
    const auto rewritten = must(seal_record(keys, address, largest));
    EXPECT_NE(term, must(root_term(keys, address, rewritten)));
    auto other_payload = *record;
    other_payload.at(crypto::aead_nonce_size) = static_cast<std::uint8_t>(other_payload.at(crypto::aead_nonce_size) ^ 0x01U);
    EXPECT_EQ(term, must(root_term(keys, address, other_payload)));
}

TEST(VaultRecords, NeedEveryKey)
{
    const RecordAddress address{.type = 1, .id = Bytes{1, 2}, .counter = 1};
    const wire::Manifest manifest{.epoch = 1, .types = {}};
    auto without_record = must(fresh_keys());
    without_record.record = SecretBytes{};
    auto without_manifest = must(fresh_keys());
    without_manifest.manifest = SecretBytes{};
    auto without_root = must(fresh_keys());
    without_root.root = SecretBytes{};
    for (const Keys* keys : {&without_record, &without_manifest, &without_root}) {
        EXPECT_EQ(test::error_of(seal_record(*keys, address, Bytes{1})), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(root_term(*keys, address, Bytes(crypto::aead_overhead))), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(manifest_tag(*keys, manifest)), Error::invalid_parameters);
    }
}

TEST(VaultManifest, RefusesAnythingElse)
{
    const auto keys = must(fresh_keys());
    const wire::Manifest manifest{
        .epoch = 5, .types = {wire::ManifestEntry{.type = 1, .count = 2, .root = Root{}}}};
    const auto tag = must(manifest_tag(keys, manifest));
    EXPECT_TRUE(check_manifest(keys, manifest, tag, 5).has_value());
    EXPECT_EQ(test::error_of(check_manifest(keys, manifest, tag, 4)), Error::integrity);
    EXPECT_EQ(test::error_of(check_manifest(keys, manifest, crypto::ByteView(tag).first(31), 5)), Error::integrity);
    EXPECT_EQ(test::error_of(check_manifest(must(fresh_keys()), manifest, tag, 5)), Error::integrity);
    auto other = manifest;
    other.types.front().count = 3;
    EXPECT_EQ(test::error_of(check_manifest(keys, other, tag, 5)), Error::integrity);
    EXPECT_EQ(test::error_of(manifest_tag(Keys{}, manifest)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(check_manifest(Keys{}, manifest, tag, 5)), Error::invalid_parameters);
    auto unordered = manifest;
    unordered.types.push_back(wire::ManifestEntry{.type = 0, .count = 1, .root = Root{}});
    auto empty_type = manifest;
    empty_type.types.at(0).count = 0;
    wire::Manifest too_many{.epoch = 5, .types = {}};
    for (std::size_t type = 0; type <= wire::manifest_types_bound; ++type) {
        too_many.types.push_back(wire::ManifestEntry{.type = static_cast<std::uint8_t>(type), .count = 1, .root = Root{}});
    }
    for (const auto* refused : {&unordered, &empty_type, &too_many}) {
        EXPECT_FALSE(wire::is_canonical(*refused));
        EXPECT_EQ(test::error_of(manifest_tag(keys, *refused)), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(check_manifest(keys, *refused, tag, 5)), Error::integrity);
    }
    EXPECT_TRUE(wire::is_canonical(manifest));
}

Root random_root()
{
    const auto bytes = test::random_bytes_of(wire::manifest_root_size);
    Root root{};
    std::ranges::copy(bytes, root.begin());
    return root;
}

RC_GTEST_PROP(VaultRootProperties, RemovingATermUndoesAddingIt, ())
{
    const auto root = random_root();
    const auto term = random_root();
    RC_ASSERT(remove_term(add_term(root, term), term) == root);
    RC_ASSERT(add_term(remove_term(root, term), term) == root);
}

RC_GTEST_PROP(VaultRootProperties, OrderDoesNotMatter, ())
{
    const auto root = random_root();
    const auto first = random_root();
    const auto second = random_root();
    RC_ASSERT(add_term(add_term(root, first), second) == add_term(add_term(root, second), first));
    RC_ASSERT(add_term(root, Root{}) == root);
    RC_ASSERT(remove_term(root, root) == Root{});
}

}
}
