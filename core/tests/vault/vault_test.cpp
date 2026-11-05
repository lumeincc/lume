// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/keys.hpp"
#include "vault/records.hpp"
#include "vault/vault_internal.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/random.hpp"
#include "lume/wire/codec.hpp"
#include "support/expected.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace lume::vault {
namespace {

using crypto::Bytes;
using crypto::ByteView;
using crypto::SecretBytes;
using wire::HardwareMode;

constexpr std::uint64_t last_epoch = std::numeric_limits<std::uint64_t>::max();

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

Nonce nonce_field(const nlohmann::json& object, const char* name)
{
    return array_of<crypto::aead_nonce_size>(hex_field(object, name));
}

std::uint64_t number_field(const nlohmann::json& object, const char* name)
{
    return std::stoull(object.at(name).get<std::string>());
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
    if (name == "invalid_parameters") {
        return Error::invalid_parameters;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

const nlohmann::json& vectors()
{
    static const auto loaded = test::load_vectors("lume/vault.json");
    return loaded;
}

const nlohmann::json& named(const nlohmann::json& list, std::string_view name)
{
    for (const auto& entry : list) {
        if (entry.at("name").get<std::string>() == name) {
            return entry;
        }
    }
    throw std::runtime_error("the vectors lack an entry the test names");
}

const nlohmann::json& header_vector(std::string_view name)
{
    return named(vectors().at("headers"), name);
}

const PassphraseKey& passphrase_key(std::string_view name)
{
    static std::map<std::string, PassphraseKey, std::less<>> derived;
    if (const auto found = derived.find(name); found != derived.end()) {
        return found->second;
    }
    const auto& vector = named(vectors().at("argon2id"), name);
    auto key = must(derive_passphrase_key(text_of(hex_field(vector, "passphrase")),
        array_of<wire::vault_salt_size>(hex_field(vector, "salt")),
        Cost{.ops = vector.at("ops").get<std::uint32_t>(), .mem = vector.at("mem").get<std::uint32_t>()}, Platform::desktop));
    return derived.emplace(std::string(name), std::move(key)).first->second;
}

KeyName name_of(const nlohmann::json& hardware)
{
    KeyName name{.mode = static_cast<HardwareMode>(hardware.at("mode").get<std::uint8_t>()),
        .epoch = hardware.at("epoch").get<std::uint64_t>(),
        .point = std::nullopt};
    if (!hardware.at("point").is_null()) {
        name.point = array_of<wire::tpm_point_size>(hex_field(hardware, "point"));
    }
    return name;
}

HardwareKey hardware_of(const nlohmann::json& hardware)
{
    return must(hardware_key(name_of(hardware), hex_field(hardware, "output")));
}

MasterKey master_from(std::string_view passphrase, const KeyName& name, ByteView output)
{
    return must(derive_master_key(passphrase_key(passphrase), must(hardware_key(name, output))));
}

MasterKey master_of(const nlohmann::json& vector)
{
    return must(derive_master_key(passphrase_key(vector.at("passphrase").get<std::string>()), hardware_of(vector.at("hardware"))));
}

wire::VaultHeader header_of(const nlohmann::json& vector)
{
    return must(wire::decode(hex_field(vector, "encoded"), wire::read_vault_header));
}

OpenedHeader vector_header(std::string_view name)
{
    const auto& vector = header_vector(name);
    return must(open_header(master_of(vector), header_of(vector)));
}

const OpenedHeader& first_opened()
{
    static const auto opened = vector_header("keystore_first");
    return opened;
}

const Keys& vector_keys()
{
    return first_opened().keys();
}

RecordAddress address_of(const nlohmann::json& vector)
{
    return RecordAddress{
        .type = vector.at("type").get<std::uint8_t>(), .id = hex_field(vector, "id"), .counter = number_field(vector, "counter")};
}

std::string short_record_under(const Keys& keys)
{
    const auto& vector = named(vectors().at("records"), "short");
    return test::to_hex(must(detail::seal_record(keys, address_of(vector), hex_field(vector, "payload"), nonce_field(vector, "nonce"))));
}

template <typename Enum>
Enum outside_of(std::underlying_type_t<Enum> value)
{
    return std::bit_cast<Enum>(value);
}

Limits limits_for(Platform platform)
{
    const auto limits = limits_of(platform);
    if (!limits) {
        throw std::runtime_error("a platform the core supports has no limits");
    }
    return *limits;
}

Bytes random_output()
{
    const auto bytes = crypto::random_public_bytes<hardware_secret_size>();
    return {bytes.begin(), bytes.end()};
}

KeyName keystore_name(std::uint64_t epoch)
{
    return KeyName{.mode = HardwareMode::keystore, .epoch = epoch, .point = std::nullopt};
}

TpmPoint vector_point()
{
    return array_of<wire::tpm_point_size>(hex_field(header_vector("tpm_first").at("hardware"), "point"));
}

TpmPoint other_point()
{
    auto point = vector_point();
    point.back() = static_cast<std::uint8_t>(point.back() ^ 0x01U);
    return point;
}

KeyName tpm_name(const TpmPoint& point, std::uint64_t epoch)
{
    return KeyName{.mode = HardwareMode::tpm, .epoch = epoch, .point = point};
}

wire::VaultHeader sealed_by_hand(std::string_view passphrase, ByteView hardware_secret, const KeyName& name, std::uint64_t epoch)
{
    const auto& argon = named(vectors().at("argon2id"), passphrase);
    const auto kpw = secret_field(argon, "key");
    const auto master = must(crypto::hkdf_sha256(hardware_secret, kpw.view(), crypto::label("vault/master"), key_size));
    wire::VaultHeader header{
        .salt = array_of<wire::vault_salt_size>(hex_field(argon, "salt")),
        .ops = argon.at("ops").get<std::uint32_t>(),
        .mem = argon.at("mem").get<std::uint32_t>(),
        .hw_mode = name.mode,
        .tpm_point = name.point,
        .wrapped_data_key = {},
        .epoch = epoch,
        .check = {}};
    const auto nonce = crypto::random_public_bytes<crypto::aead_nonce_size>();
    const auto wrapped = must(crypto::detail::aead_encrypt(
        master, nonce, crypto::label("vault/data-key"), secret_field(vectors().at("keys"), "data_key").view()));
    const std::span wrapped_data_key(header.wrapped_data_key);
    std::ranges::copy(nonce, wrapped_data_key.begin());
    std::ranges::copy(wrapped, wrapped_data_key.subspan(nonce.size()).begin());
    const auto check_key =
        must(crypto::hkdf_sha256(Bytes(key_size, 0), master.view(), crypto::label("vault/check-key"), key_size));
    auto message = crypto::label("vault/check");
    const auto unsigned_header = wire::encode_unsigned(header);
    message.insert(message.end(), unsigned_header.begin(), unsigned_header.end());
    const auto check = crypto::hmac_sha256(check_key.view(), message);
    std::ranges::copy(check.view(), header.check.begin());
    return header;
}

Root independent_term(const RecordAddress& address, const Nonce& nonce)
{
    static const auto root_key = must(crypto::hkdf_sha256(
        Bytes(key_size, 0), secret_field(vectors().at("keys"), "data_key").view(), crypto::label("vault/root-key"), key_size));
    const auto message =
        crypto::Encoder{}.label("vault/root").u8(address.type).prefixed(address.id).u64(address.counter).raw(nonce).take();
    const auto tag = crypto::hmac_sha256(root_key.view(), message);
    return array_of<wire::manifest_root_size>(Bytes(tag.view().begin(), tag.view().end()));
}

std::vector<wire::ManifestEntry> types_of(const nlohmann::json& list)
{
    std::vector<wire::ManifestEntry> types;
    for (const auto& entry : list) {
        types.push_back(wire::ManifestEntry{.type = entry.at("type").get<std::uint8_t>(),
            .count = entry.at("count").get<std::uint32_t>(),
            .root = array_of<wire::manifest_root_size>(hex_field(entry, "root"))});
    }
    return types;
}

std::vector<wire::ManifestEntry> types_up_to(std::size_t count)
{
    std::vector<wire::ManifestEntry> types;
    for (std::size_t type = 1; type <= count; ++type) {
        types.push_back(wire::ManifestEntry{.type = static_cast<std::uint8_t>(type), .count = 1, .root = Root{}});
    }
    return types;
}

TEST(VaultKeys, MatchTheLumeVectors)
{
    const auto& keys = vectors().at("keys");
    const auto& floor = passphrase_key(keys.at("passphrase").get<std::string>());
    const auto keystore_input = hardware_input(floor, HardwareMode::keystore);
    ASSERT_TRUE(keystore_input.has_value());
    EXPECT_EQ(test::to_hex(keystore_input->view()), keys.at("keystore_input").get<std::string>());
    const auto authorisation = hardware_input(floor, HardwareMode::tpm);
    ASSERT_TRUE(authorisation.has_value());
    EXPECT_EQ(test::to_hex(authorisation->view()), keys.at("tpm_authorisation").get<std::string>());
    EXPECT_FALSE(keystore_input->equals(authorisation->view()));
    const auto software = hardware_input(floor, HardwareMode::software);
    ASSERT_TRUE(software.has_value());
    EXPECT_EQ(software->size(), 0U);
    EXPECT_EQ(test::error_of(hardware_input(floor, outside_of<HardwareMode>(0))), Error::invalid_parameters);

    int keystore_outputs = 0;
    for (const auto& vector : vectors().at("headers")) {
        const auto& hardware = vector.at("hardware");
        if (name_of(hardware).mode != HardwareMode::keystore) {
            continue;
        }
        const auto input = must(hardware_input(passphrase_key(vector.at("passphrase").get<std::string>()), HardwareMode::keystore));
        const auto seed = "LUME vault vector keystore key " + std::to_string(hardware.at("epoch").get<std::uint64_t>());
        const auto device_key = crypto::sha256(Bytes(seed.begin(), seed.end()));
        EXPECT_EQ(test::to_hex(crypto::hmac_sha256(device_key, input.view()).view()), hardware.at("output").get<std::string>());
        ++keystore_outputs;
    }
    EXPECT_EQ(keystore_outputs, 3);
}

TEST(VaultHeader, MatchesTheLumeVectors)
{
    const auto data_key = secret_field(vectors().at("keys"), "data_key");
    const auto expected_record = named(vectors().at("records"), "short").at("record").get<std::string>();
    std::map<std::string, OpenedHeader> built;
    for (const auto& vector : vectors().at("headers")) {
        const auto name = vector.at("name").get<std::string>();
        const auto nonce = nonce_field(vector, "nonce");
        auto header = [&]() -> Result<OpenedHeader> {
            if (vector.at("from").is_null()) {
                return detail::first_header(master_of(vector), data_key, nonce);
            }
            const auto& from_vector = header_vector(vector.at("from").get<std::string>());
            const auto& from = built.at(from_vector.at("name").get<std::string>());
            if (from_vector.at("passphrase") == vector.at("passphrase")) {
                return detail::next_header(hardware_of(vector.at("hardware")), from, nonce);
            }
            return detail::rekeyed_header(master_of(vector), from, must(confirm(master_of(from_vector), from)), nonce);
        }();
        ASSERT_TRUE(header.has_value()) << name;
        const auto& sealed = header->header();
        EXPECT_EQ(sealed.epoch, vector.at("epoch").get<std::uint64_t>()) << name;
        EXPECT_EQ(test::to_hex(sealed.wrapped_data_key), vector.at("wrapped_data_key").get<std::string>()) << name;
        EXPECT_EQ(test::to_hex(sealed.check), vector.at("check").get<std::string>()) << name;
        EXPECT_EQ(test::to_hex(wire::encode(sealed)), vector.at("encoded").get<std::string>()) << name;
        EXPECT_EQ(header->hardware(), name_of(vector.at("hardware"))) << name;
        EXPECT_EQ(short_record_under(header->keys()), expected_record) << name;

        const auto opened = open_header(master_of(vector), header_of(vector));
        ASSERT_TRUE(opened.has_value()) << name;
        EXPECT_EQ(opened->header(), sealed) << name;
        EXPECT_EQ(opened->hardware(), header->hardware()) << name;
        EXPECT_EQ(short_record_under(opened->keys()), expected_record) << name;
        built.emplace(name, std::move(*header));
    }
    EXPECT_EQ(built.size(), 6U);
}

TEST(VaultHeader, RefusesTheLumeVectors)
{
    int refused = 0;
    for (const auto& refusal : vectors().at("header_refusals")) {
        EXPECT_EQ(test::error_of(open_header(master_of(refusal), header_of(refusal))),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 10);
}

TEST(VaultHeader, SalvagesKeysOnlyWhenTheCheckAloneFails)
{
    const auto& refusals = vectors().at("header_refusals");
    const auto& tampered = named(refusals, "tampered_check");
    const auto salvaged = salvage_keys(master_of(tampered), header_of(tampered));
    ASSERT_TRUE(salvaged.has_value());
    EXPECT_EQ(short_record_under(*salvaged), named(vectors().at("records"), "short").at("record").get<std::string>());

    const auto refused = [&refusals](std::string_view name) {
        const auto& vector = named(refusals, name);
        return test::error_of(salvage_keys(master_of(vector), header_of(vector)));
    };
    EXPECT_EQ(refused("data_key_does_not_unwrap"), Error::integrity);
    EXPECT_EQ(refused("another_hardware_key"), Error::wrong_passphrase);
    EXPECT_EQ(refused("another_passphrase"), Error::wrong_passphrase);
    EXPECT_EQ(refused("ops_below_floor"), Error::integrity);
    EXPECT_EQ(refused("mem_above_ceiling"), Error::integrity);
    EXPECT_EQ(refused("another_salt"), Error::invalid_parameters);
    EXPECT_EQ(refused("another_epoch"), Error::invalid_parameters);
    const auto& first = header_vector("keystore_first");
    EXPECT_EQ(test::error_of(salvage_keys(master_of(first), header_of(first))), Error::invalid_parameters);
}

TEST(VaultHeader, IsBoundToTheCostAndTheTpmKeyOfItsMasterKey)
{
    const auto& first = header_vector("keystore_first");
    const auto& argon = named(vectors().at("argon2id"), "floor");
    const auto dearer = must(derive_passphrase_key(text_of(hex_field(argon, "passphrase")),
        array_of<wire::vault_salt_size>(hex_field(argon, "salt")), Cost{.ops = 3, .mem = cost_floor.mem}, Platform::desktop));
    const auto master = must(derive_master_key(dearer, hardware_of(first.at("hardware"))));
    EXPECT_EQ(test::error_of(open_header(master, header_of(first))), Error::invalid_parameters);

    const auto& tpm = header_vector("tpm_first");
    const auto output = hex_field(tpm.at("hardware"), "output");
    EXPECT_EQ(test::error_of(open_header(master_from("floor", tpm_name(other_point(), 1), output), header_of(tpm))),
        Error::invalid_parameters);
    EXPECT_TRUE(open_header(master_from("floor", tpm_name(vector_point(), 7), output), header_of(tpm)).has_value());
    EXPECT_EQ(test::error_of(open_header(master_from("floor", keystore_name(1), output), header_of(tpm))),
        Error::invalid_parameters);
}

TEST(VaultHeader, StartsAtTheFirstEpoch)
{
    const auto master = master_from("floor", keystore_name(1), random_output());
    const auto first = first_header(master);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->header().epoch, first_epoch);
    EXPECT_EQ(first->hardware(), keystore_name(1));
    const auto opened = open_header(master, first->header());
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(short_record_under(opened->keys()), short_record_under(first->keys()));
    const auto second = first_header(master);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->header().wrapped_data_key, second->header().wrapped_data_key);
    EXPECT_NE(short_record_under(first->keys()), short_record_under(second->keys()));

    EXPECT_EQ(test::error_of(first_header(master_from("floor", keystore_name(2), random_output()))), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(detail::first_header(master, SecretBytes(key_size - 1), Nonce{})), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(detail::first_header(master, SecretBytes(key_size + 1), Nonce{})), Error::invalid_parameters);
}

TEST(VaultHeader, MovesToTheNextEpochOnlyWithTheNextKey)
{
    const auto current = vector_header("keystore_first");
    const auto& next_vector = header_vector("keystore_next");
    const auto next = next_header(hardware_of(next_vector.at("hardware")), current);
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->header().epoch, 2U);
    EXPECT_EQ(next->header().salt, current.header().salt);
    EXPECT_EQ(next->hardware(), keystore_name(2));
    EXPECT_EQ(short_record_under(next->keys()), short_record_under(current.keys()));
    EXPECT_TRUE(open_header(master_of(next_vector), next->header()).has_value());
    EXPECT_EQ(test::error_of(open_header(master_of(header_vector("keystore_first")), next->header())), Error::invalid_parameters);

    for (const auto epoch : {std::uint64_t{1}, std::uint64_t{3}}) {
        EXPECT_EQ(test::error_of(next_header(must(hardware_key(keystore_name(epoch), random_output())), current)),
            Error::invalid_parameters);
    }
    EXPECT_EQ(test::error_of(next_header(must(hardware_key(KeyName{.mode = HardwareMode::software, .epoch = 2, .point = {}},
                                                   random_output())),
                  current)),
        Error::invalid_parameters);

    const auto software = vector_header("software_first");
    const auto rotated = next_header(must(hardware_key(KeyName{.mode = HardwareMode::software, .epoch = 2, .point = {}},
                                          random_output())),
        software);
    ASSERT_TRUE(rotated.has_value());
    EXPECT_EQ(rotated->header().epoch, 2U);

    const auto tpm = vector_header("tpm_first");
    const auto output = hex_field(header_vector("tpm_first").at("hardware"), "output");
    const auto same_key = next_header(must(hardware_key(tpm_name(vector_point(), 1), output)), tpm);
    ASSERT_TRUE(same_key.has_value());
    EXPECT_EQ(same_key->header().epoch, 2U);
    EXPECT_EQ(same_key->header().tpm_point, vector_point());
    EXPECT_EQ(test::error_of(next_header(must(hardware_key(tpm_name(other_point(), 1), output)), tpm)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(next_header(must(hardware_key(keystore_name(2), output)), tpm)), Error::invalid_parameters);
}

TEST(VaultHeader, RefusesToMovePastTheLastEpoch)
{
    const auto output = random_output();
    const auto master = master_from("floor", keystore_name(last_epoch), output);
    const auto last = open_header(master, sealed_by_hand("floor", output, keystore_name(last_epoch), last_epoch));
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(test::error_of(next_header(must(hardware_key(keystore_name(last_epoch), random_output())), *last)),
        Error::integrity);
    const auto confirmed = must(confirm(master, *last));
    EXPECT_EQ(test::error_of(rekeyed_header(master_from("changed", keystore_name(last_epoch), random_output()), *last, confirmed)),
        Error::integrity);

    const auto before_last = open_header(
        master_from("floor", keystore_name(last_epoch - 1), output), sealed_by_hand("floor", output, keystore_name(last_epoch - 1), last_epoch - 1));
    ASSERT_TRUE(before_last.has_value());
    const auto moved = next_header(must(hardware_key(keystore_name(last_epoch), random_output())), *before_last);
    ASSERT_TRUE(moved.has_value());
    EXPECT_EQ(moved->header().epoch, last_epoch);
}

TEST(VaultHeader, ChangesThePassphraseOnlyWhenConfirmed)
{
    const auto current = vector_header("keystore_next");
    const auto& next_vector = header_vector("keystore_next");
    const auto confirmed = confirm(master_of(next_vector), current);
    ASSERT_TRUE(confirmed.has_value());
    EXPECT_EQ(confirmed->check(), current.header().check);

    const auto rekeyed = rekeyed_header(master_of(header_vector("keystore_rekeyed")), current, *confirmed);
    ASSERT_TRUE(rekeyed.has_value());
    EXPECT_EQ(rekeyed->header().epoch, 3U);
    EXPECT_EQ(rekeyed->header().salt, header_of(header_vector("keystore_rekeyed")).salt);
    EXPECT_EQ(rekeyed->hardware(), keystore_name(3));
    EXPECT_EQ(short_record_under(rekeyed->keys()), short_record_under(current.keys()));

    const auto& first_vector = header_vector("keystore_first");
    const auto stale = must(confirm(master_of(first_vector), vector_header("keystore_first")));
    const auto changed = master_from("changed", keystore_name(3), random_output());
    EXPECT_EQ(test::error_of(rekeyed_header(changed, current, stale)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(rekeyed_header(master_from("floor", keystore_name(3), random_output()), current, *confirmed)),
        Error::invalid_parameters);
    for (const auto epoch : {std::uint64_t{2}, std::uint64_t{4}}) {
        EXPECT_EQ(test::error_of(rekeyed_header(master_from("changed", keystore_name(epoch), random_output()), current, *confirmed)),
            Error::invalid_parameters);
    }
    EXPECT_EQ(test::error_of(rekeyed_header(master_from("changed",
                                                 KeyName{.mode = HardwareMode::software, .epoch = 3, .point = {}}, random_output()),
                  current, *confirmed)),
        Error::invalid_parameters);

    EXPECT_EQ(test::error_of(confirm(master_of(first_vector), current)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(confirm(master_from("floor", keystore_name(2), random_output()), current)), Error::wrong_passphrase);
    EXPECT_EQ(test::error_of(confirm(master_from("another", keystore_name(2), random_output()), current)), Error::wrong_passphrase);

    const auto tpm = vector_header("tpm_first");
    const auto tpm_confirmed = must(confirm(master_of(header_vector("tpm_first")), tpm));
    const auto moved = rekeyed_header(master_from("changed", tpm_name(other_point(), 2), random_output()), tpm, tpm_confirmed);
    ASSERT_TRUE(moved.has_value());
    EXPECT_EQ(moved->header().tpm_point, other_point());
    EXPECT_EQ(moved->header().epoch, 2U);
    EXPECT_EQ(test::error_of(rekeyed_header(master_from("changed", tpm_name(vector_point(), 2), random_output()), tpm, tpm_confirmed)),
        Error::invalid_parameters);
    EXPECT_EQ(test::error_of(rekeyed_header(master_from("changed", tpm_name(other_point(), 1), random_output()), tpm, tpm_confirmed)),
        Error::invalid_parameters);
}

TEST(VaultHeader, GivesTheHardwareInputOfItsOwnPassphraseKeyUntilItForgetsIt)
{
    const auto& floor = passphrase_key("floor");
    auto current = vector_header("keystore_first");
    const auto keystore = hardware_input(current);
    ASSERT_TRUE(keystore.has_value());
    EXPECT_TRUE(keystore->equals(must(hardware_input(floor, HardwareMode::keystore)).view()));
    const auto tpm = hardware_input(vector_header("tpm_first"));
    ASSERT_TRUE(tpm.has_value());
    EXPECT_TRUE(tpm->equals(must(hardware_input(floor, HardwareMode::tpm)).view()));
    const auto software = hardware_input(vector_header("software_first"));
    ASSERT_TRUE(software.has_value());
    EXPECT_EQ(software->size(), 0U);

    const auto& first_vector = header_vector("keystore_first");
    const auto next = next_header(hardware_of(header_vector("keystore_next").at("hardware")), current);
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(must(hardware_input(*next)).equals(keystore->view()));

    current.forget_passphrase();
    EXPECT_EQ(test::error_of(hardware_input(current)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(next_header(hardware_of(header_vector("keystore_next").at("hardware")), current)),
        Error::invalid_parameters);
    auto forgotten_software = vector_header("software_first");
    forgotten_software.forget_passphrase();
    EXPECT_EQ(test::error_of(hardware_input(forgotten_software)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(next_header(must(hardware_key(KeyName{.mode = HardwareMode::software, .epoch = 2, .point = {}},
                                                   random_output())),
                  forgotten_software)),
        Error::invalid_parameters);

    const auto manifest = seal_manifest(current, types_up_to(1));
    ASSERT_TRUE(manifest.has_value());
    EXPECT_TRUE(open_manifest(current, *manifest).has_value());
    const auto confirmed = confirm(master_of(first_vector), current);
    ASSERT_TRUE(confirmed.has_value());
    const auto rekeyed = rekeyed_header(master_from("changed", keystore_name(2), random_output()), current, *confirmed);
    ASSERT_TRUE(rekeyed.has_value());
    EXPECT_TRUE(must(hardware_input(*rekeyed)).equals(must(hardware_input(passphrase_key("changed"), HardwareMode::keystore)).view()));
}

TEST(VaultKeys, NameHardwareKeysExactly)
{
    const auto output = random_output();
    EXPECT_TRUE(hardware_key(keystore_name(1), output).has_value());
    EXPECT_TRUE(hardware_key(tpm_name(vector_point(), 1), output).has_value());
    auto compressed = vector_point();
    compressed.front() = 0x02;
    for (const auto& name : {KeyName{.mode = outside_of<HardwareMode>(0), .epoch = 1, .point = {}},
             KeyName{.mode = outside_of<HardwareMode>(4), .epoch = 1, .point = {}}, keystore_name(0),
             KeyName{.mode = HardwareMode::keystore, .epoch = 1, .point = vector_point()},
             KeyName{.mode = HardwareMode::software, .epoch = 1, .point = vector_point()},
             KeyName{.mode = HardwareMode::tpm, .epoch = 1, .point = {}}, tpm_name(compressed, 1)}) {
        EXPECT_EQ(test::error_of(hardware_key(name, output)), Error::invalid_parameters);
    }
    for (const auto& name : {keystore_name(1), tpm_name(vector_point(), 1)}) {
        EXPECT_EQ(test::error_of(hardware_key(name, Bytes(hardware_secret_size - 1, 1))), Error::hardware_failure);
        EXPECT_EQ(test::error_of(hardware_key(name, Bytes(hardware_secret_size + 1, 1))), Error::hardware_failure);
        EXPECT_EQ(test::error_of(hardware_key(name, Bytes(hardware_secret_size, 0))), Error::hardware_failure);
    }
    Bytes last_byte(hardware_secret_size, 0);
    last_byte.back() = 1;
    EXPECT_TRUE(hardware_key(keystore_name(1), last_byte).has_value());
    const auto key = must(hardware_key(tpm_name(vector_point(), 9), output));
    EXPECT_EQ(key.name(), tpm_name(vector_point(), 9));
}

TEST(VaultKeys, KeepCostsWithinTheirCeiling)
{
    EXPECT_TRUE(within_bounds(cost_floor, cost_ceiling));
    EXPECT_TRUE(within_bounds(cost_ceiling, cost_ceiling));
    for (const auto platform : {Platform::android, Platform::desktop}) {
        const auto limits = limits_for(platform);
        EXPECT_TRUE(within_bounds(limits.cost, limits.ceiling));
        EXPECT_TRUE(within_bounds(limits.ceiling, cost_ceiling));
    }
    EXPECT_EQ(limits_for(Platform::android).cost, (Cost{.ops = 3, .mem = 64 * kib_per_mib}));
    EXPECT_EQ(limits_for(Platform::android).ceiling, (Cost{.ops = 4, .mem = 256 * kib_per_mib}));
    EXPECT_EQ(limits_for(Platform::desktop).cost, (Cost{.ops = 3, .mem = 256 * kib_per_mib}));
    EXPECT_EQ(limits_for(Platform::desktop).ceiling, cost_ceiling);
    EXPECT_FALSE(limits_of(outside_of<Platform>(0)).has_value());
    EXPECT_FALSE(limits_of(outside_of<Platform>(3)).has_value());
    const auto android = android_limits.ceiling;
    EXPECT_TRUE(within_bounds(android, android));
    EXPECT_FALSE(within_bounds(Cost{.ops = android.ops + 1, .mem = android.mem}, android));
    EXPECT_FALSE(within_bounds(Cost{.ops = android.ops, .mem = android.mem + 1}, android));
    EXPECT_FALSE(within_bounds(cost_floor, Cost{.ops = cost_floor.ops - 1, .mem = cost_floor.mem}));
    EXPECT_FALSE(within_bounds(cost_floor, Cost{.ops = cost_ceiling.ops + 1, .mem = cost_ceiling.mem}));
    EXPECT_FALSE(within_bounds(cost_floor, Cost{.ops = cost_ceiling.ops, .mem = cost_ceiling.mem + 1}));
    EXPECT_FALSE(within_bounds(cost_floor, Cost{.ops = cost_ceiling.ops, .mem = cost_floor.mem - 1}));

    const Salt salt{};
    for (const auto cost : {Cost{.ops = cost_floor.ops - 1, .mem = cost_floor.mem},
             Cost{.ops = cost_ceiling.ops + 1, .mem = cost_floor.mem}, Cost{.ops = cost_floor.ops, .mem = cost_floor.mem - 1},
             Cost{.ops = cost_floor.ops, .mem = cost_ceiling.mem + 1}, Cost{.ops = 0xffffffffU, .mem = cost_floor.mem},
             Cost{.ops = cost_floor.ops, .mem = 0xffffffffU}}) {
        EXPECT_FALSE(within_bounds(cost, cost_ceiling));
        for (const auto platform : {Platform::android, Platform::desktop}) {
            EXPECT_EQ(test::error_of(derive_passphrase_key("passphrase", salt, cost, platform)), Error::integrity);
        }
    }
    for (const auto cost : {Cost{.ops = android.ops + 1, .mem = cost_floor.mem}, Cost{.ops = cost_floor.ops, .mem = android.mem + 1},
             cost_ceiling}) {
        EXPECT_EQ(test::error_of(derive_passphrase_key("passphrase", salt, cost, Platform::android)), Error::integrity);
    }
    for (const auto platform : {outside_of<Platform>(0), outside_of<Platform>(3)}) {
        EXPECT_EQ(test::error_of(derive_passphrase_key("passphrase", salt, cost_floor, platform)), Error::invalid_parameters);
    }
    EXPECT_EQ(test::error_of(derive_passphrase_key(std::string(passphrase_bound + 1, 'a'), salt, cost_floor, Platform::android)),
        Error::invalid_passphrase);
    const auto longest = derive_passphrase_key(std::string(passphrase_bound, 'a'), salt, cost_floor, Platform::android);
    ASSERT_TRUE(longest.has_value());
    EXPECT_EQ(longest->salt(), salt);
    EXPECT_EQ(longest->cost(), cost_floor);
}

TEST(VaultKeys, RotateOnlyTheKeysTheCoreCanReplace)
{
    EXPECT_TRUE(rotates(HardwareMode::keystore));
    EXPECT_TRUE(rotates(HardwareMode::software));
    EXPECT_FALSE(rotates(HardwareMode::tpm));
    EXPECT_FALSE(rotates(outside_of<HardwareMode>(0)));
    const auto header = header_of(header_vector("keystore_next"));
    EXPECT_TRUE(well_formed(header));
    EXPECT_TRUE(names(header, keystore_name(2)));
    EXPECT_FALSE(names(header, keystore_name(1)));
    auto unnamed = header;
    unnamed.epoch = 0;
    EXPECT_FALSE(well_formed(unnamed));
    const auto tpm = header_of(header_vector("tpm_next"));
    EXPECT_TRUE(names(tpm, tpm_name(vector_point(), 1)));
    EXPECT_TRUE(names(tpm, tpm_name(vector_point(), 2)));
    EXPECT_FALSE(names(tpm, tpm_name(other_point(), 2)));
    EXPECT_FALSE(names(tpm, KeyName{.mode = HardwareMode::tpm, .epoch = 2, .point = {}}));
}

TEST(VaultKeys, CheckNewPassphrases)
{
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

TEST(VaultRecords, MatchTheLumeVectors)
{
    const auto& keys = vector_keys();
    const auto hasher = must(TermHasher::of(keys));
    SecretBytes scratch;
    int checked = 0;
    for (const auto& vector : vectors().at("records")) {
        const auto name = vector.at("name").get<std::string>();
        const auto address = address_of(vector);
        const auto payload = hex_field(vector, "payload");
        const auto nonce = nonce_field(vector, "nonce");
        const auto record = detail::seal_record(keys, address, payload, nonce);
        ASSERT_TRUE(record.has_value()) << name;
        EXPECT_EQ(test::to_hex(*record), vector.at("record").get<std::string>()) << name;
        EXPECT_EQ(record->size(), crypto::aead_overhead + vector.at("padded_size").get<std::size_t>()) << name;
        EXPECT_EQ(nonce_of(*record), nonce) << name;
        const auto opened = open_record(keys, address, nonce, *record);
        ASSERT_TRUE(opened.has_value()) << name;
        EXPECT_TRUE(opened->equals(payload)) << name;

        const auto slot = number_field(vector, "slot");
        const auto sealed = detail::seal_address(keys, slot, Located{.address = address, .nonce = nonce}, nonce_field(vector, "address_nonce"));
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(test::to_hex(*sealed), vector.at("address").get<std::string>()) << name;
        const auto located = open_address(keys, slot, *sealed, scratch);
        ASSERT_TRUE(located.has_value()) << name;
        EXPECT_EQ(located->address.type, address.type) << name;
        EXPECT_EQ(located->address.id, address.id) << name;
        EXPECT_EQ(located->address.counter, address.counter) << name;
        EXPECT_EQ(located->nonce, nonce) << name;

        const auto term = root_term(keys, address, nonce);
        ASSERT_TRUE(term.has_value()) << name;
        EXPECT_EQ(test::to_hex(*term), vector.at("root_term").get<std::string>()) << name;
        EXPECT_EQ(hasher.term(address, nonce), term) << name;
        EXPECT_EQ(independent_term(address, nonce), *term) << name;
        ++checked;
    }
    EXPECT_EQ(checked, 6);
}

TEST(VaultRecords, RefuseTheLumeVectors)
{
    const auto& keys = vector_keys();
    int refused = 0;
    for (const auto& refusal : vectors().at("record_refusals")) {
        EXPECT_EQ(test::error_of(open_record(keys, address_of(refusal), nonce_field(refusal, "expected"), hex_field(refusal, "record"))),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 11);

    SecretBytes scratch;
    for (const auto& refusal : vectors().at("address_refusals")) {
        EXPECT_EQ(test::error_of(open_address(keys, number_field(refusal, "slot"), hex_field(refusal, "address"), scratch)),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 18);
}

TEST(VaultRecords, OpenAnEarlierWriteOnlyWhereItsOwnNonceIsExpected)
{
    const auto& keys = vector_keys();
    const auto& earlier = vectors().at("earlier_write");
    const auto& current = named(vectors().at("records"), "short");
    const auto address = address_of(current);
    const auto opened = open_record(keys, address, nonce_field(earlier, "nonce"), hex_field(earlier, "record"));
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->equals(hex_field(earlier, "payload")));
    EXPECT_EQ(test::error_of(open_record(keys, address, nonce_field(current, "nonce"), hex_field(earlier, "record"))),
        Error::integrity);
    const auto term = root_term(keys, address, nonce_field(earlier, "nonce"));
    ASSERT_TRUE(term.has_value());
    EXPECT_EQ(test::to_hex(*term), earlier.at("root_term").get<std::string>());
    EXPECT_NE(test::to_hex(*term), current.at("root_term").get<std::string>());
}

TEST(VaultRecords, PadToTheSmallestBucketThatFits)
{
    const auto& keys = vector_keys();
    const RecordAddress address{.type = 4, .id = Bytes(record_id_bound, 9), .counter = 12};
    for (std::size_t index = 0; index < record_buckets.size(); ++index) {
        const auto bucket = record_buckets.at(index);
        for (const auto size : {bucket - 1, bucket}) {
            if (size > payload_bound) {
                continue;
            }
            const Bytes payload(size, 3);
            const auto record = seal_record(keys, address, payload);
            ASSERT_TRUE(record.has_value()) << size;
            const auto expected = size < bucket ? bucket : record_buckets.at(index + 1);
            EXPECT_EQ(record->size(), crypto::aead_overhead + expected) << size;
            const auto opened = open_record(keys, address, must(nonce_of(*record)), *record);
            ASSERT_TRUE(opened.has_value()) << size;
            EXPECT_TRUE(opened->equals(payload)) << size;
        }
    }
    const auto largest = seal_record(keys, address, Bytes(payload_bound, 1));
    ASSERT_TRUE(largest.has_value());
    EXPECT_EQ(largest->size(), record_maximum);
    EXPECT_EQ(test::error_of(seal_record(keys, address, Bytes(payload_bound + 1))), Error::record_too_large);
    EXPECT_EQ(record_minimum, crypto::aead_overhead + record_buckets.front());
}

TEST(VaultRecords, OpenOnlyAtTheirAddressWithinTheirSize)
{
    const auto& keys = vector_keys();
    const RecordAddress address{.type = 4, .id = Bytes{1, 2, 3}, .counter = 12};
    const auto record = must(seal_record(keys, address, Bytes{7, 7}));
    const auto nonce = must(nonce_of(record));
    EXPECT_TRUE(open_record(keys, address, nonce, record).has_value());
    EXPECT_EQ(test::error_of(nonce_of(ByteView(record).first(record_minimum - 1))), Error::integrity);
    EXPECT_EQ(nonce_of(ByteView(record).first(record_minimum)), nonce);
    EXPECT_EQ(test::error_of(open_record(keys, address, nonce, ByteView(record).first(record_minimum - 1))), Error::integrity);
    auto longer = record;
    longer.push_back(0);
    EXPECT_EQ(test::error_of(open_record(keys, address, nonce, longer)), Error::integrity);
    Bytes too_long(record_maximum + 1, 0);
    std::ranges::copy(nonce, too_long.begin());
    EXPECT_EQ(test::error_of(open_record(keys, address, nonce, too_long)), Error::integrity);

    for (const auto& invalid : {RecordAddress{.type = 0, .id = Bytes{1}, .counter = 1},
             RecordAddress{.type = 1, .id = Bytes(record_id_bound + 1, 1), .counter = 1}}) {
        EXPECT_EQ(test::error_of(seal_record(keys, invalid, Bytes{1})), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(open_record(keys, invalid, nonce, record)), Error::integrity);
        EXPECT_EQ(test::error_of(root_term(keys, invalid, nonce)), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(seal_address(keys, 1, Located{.address = invalid, .nonce = nonce})), Error::invalid_parameters);
    }

    const auto other = first_header(master_of(header_vector("keystore_first")));
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(test::error_of(open_record(other->keys(), address, nonce, record)), Error::integrity);
}

TEST(VaultRecords, TermsCoverEveryPartOfTheAddressAndTheNonce)
{
    const auto& keys = vector_keys();
    const RecordAddress address{.type = 4, .id = Bytes{1, 2, 3}, .counter = 12};
    const Nonce nonce{};
    const auto term = must(root_term(keys, address, nonce));
    EXPECT_EQ(term, must(root_term(keys, address, nonce)));
    auto other_nonce = nonce;
    other_nonce.back() = 1;
    EXPECT_NE(term, must(root_term(keys, address, other_nonce)));
    for (const auto& changed : {RecordAddress{.type = 5, .id = address.id, .counter = address.counter},
             RecordAddress{.type = address.type, .id = Bytes{1, 2}, .counter = address.counter},
             RecordAddress{.type = address.type, .id = address.id, .counter = address.counter + 1}}) {
        EXPECT_NE(term, must(root_term(keys, changed, nonce)));
    }
    const auto other = first_header(master_of(header_vector("keystore_first")));
    ASSERT_TRUE(other.has_value());
    EXPECT_NE(term, must(root_term(other->keys(), address, nonce)));
    const auto hasher = must(TermHasher::of(keys));
    const RecordAddress longest{.type = 0xff, .id = Bytes(record_id_bound, 0xff), .counter = std::numeric_limits<std::uint64_t>::max()};
    EXPECT_EQ(must(hasher.term(longest, nonce)), independent_term(longest, nonce));
    EXPECT_EQ(must(root_term(keys, longest, nonce)), independent_term(longest, nonce));
    EXPECT_EQ(test::error_of(hasher.term(RecordAddress{.type = 1, .id = Bytes(record_id_bound + 1, 0), .counter = 0}, nonce)),
        Error::invalid_parameters);
    EXPECT_EQ(test::error_of(hasher.term(RecordAddress{.type = 0, .id = Bytes{}, .counter = 0}, nonce)), Error::invalid_parameters);
}

TEST(VaultAddresses, OpenOnlyUnderTheirSlot)
{
    const auto& keys = vector_keys();
    const RecordAddress address{.type = 2, .id = Bytes(record_id_bound, 5), .counter = std::numeric_limits<std::uint64_t>::max()};
    const Located located{.address = address, .nonce = crypto::random_public_bytes<crypto::aead_nonce_size>()};
    SecretBytes scratch(3);
    for (const auto slot : {std::uint64_t{1}, slot_bound}) {
        const auto sealed = seal_address(keys, slot, located);
        ASSERT_TRUE(sealed.has_value());
        EXPECT_EQ(sealed->size(), sealed_address_size);
        const auto opened = open_address(keys, slot, *sealed, scratch);
        ASSERT_TRUE(opened.has_value());
        EXPECT_EQ(scratch.size(), wire::vault_address_size);
        EXPECT_EQ(opened->address.id, located.address.id);
        EXPECT_EQ(opened->address.counter, located.address.counter);
        EXPECT_EQ(opened->nonce, located.nonce);
        EXPECT_EQ(test::error_of(open_address(keys, slot ^ 2U, *sealed, scratch)), Error::integrity);
        EXPECT_EQ(test::error_of(open_address(keys, slot, ByteView(*sealed).first(sealed_address_size - 1), scratch)),
            Error::integrity);
        auto longer = *sealed;
        longer.push_back(0);
        EXPECT_EQ(test::error_of(open_address(keys, slot, longer, scratch)), Error::integrity);
    }
    const auto sealed = must(seal_address(keys, 1, located));
    EXPECT_EQ(test::error_of(open_address(keys, 0, sealed, scratch)), Error::integrity);
    EXPECT_EQ(test::error_of(open_address(keys, slot_bound + 1, sealed, scratch)), Error::integrity);
    EXPECT_EQ(test::error_of(seal_address(keys, 0, located)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(seal_address(keys, slot_bound + 1, located)), Error::invalid_parameters);
    EXPECT_NE(must(seal_address(keys, 1, located)), sealed);
}

TEST(VaultSlots, AreNeverZeroAndFitTheirBound)
{
    std::uint64_t seen = 0;
    for (int draw = 0; draw < 256; ++draw) {
        const auto slot = fresh_slot();
        EXPECT_GE(slot, 1U);
        EXPECT_LE(slot, slot_bound);
        seen |= slot;
    }
    EXPECT_EQ(seen, slot_bound);
}

TEST(VaultRoots, MatchTheLumeVectors)
{
    const auto& roots = vectors().at("roots");
    std::map<int, Root> sums;
    for (const auto& vector : vectors().at("records")) {
        auto& root = sums[vector.at("type").get<int>()];
        root = add_term(root, array_of<wire::manifest_root_size>(hex_field(vector, "root_term")));
    }
    EXPECT_EQ(test::to_hex(sums.at(1)), roots.at("type_1").get<std::string>());
    EXPECT_EQ(test::to_hex(sums.at(2)), roots.at("type_2").get<std::string>());
    EXPECT_EQ(test::to_hex(sums.at(3)), roots.at("type_3").get<std::string>());

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
    const auto& vector = vectors().at("manifest");
    const auto opened = vector_header(vector.at("header").get<std::string>());
    const auto types = types_of(vector.at("types"));
    const auto& roots = vectors().at("roots");
    ASSERT_EQ(types.size(), 3U);
    EXPECT_EQ(test::to_hex(types.at(0).root), roots.at("type_1").get<std::string>());
    EXPECT_EQ(test::to_hex(types.at(1).root), roots.at("type_2").get<std::string>());
    EXPECT_EQ(test::to_hex(types.at(2).root), roots.at("type_3").get<std::string>());

    const auto sealed = detail::seal_manifest(opened, types, nonce_field(vector, "nonce"));
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(test::to_hex(*sealed), vector.at("sealed").get<std::string>());
    EXPECT_EQ(sealed->size(), sealed_manifest_size);
    const auto manifest = open_manifest(opened, *sealed);
    ASSERT_TRUE(manifest.has_value());
    EXPECT_EQ(manifest->epoch, opened.header().epoch);
    EXPECT_EQ(manifest->types, types);

    const auto& empty = vector.at("empty");
    const auto sealed_empty = detail::seal_manifest(opened, {}, nonce_field(empty, "nonce"));
    ASSERT_TRUE(sealed_empty.has_value());
    EXPECT_EQ(test::to_hex(*sealed_empty), empty.at("sealed").get<std::string>());
    const auto opened_empty = open_manifest(opened, *sealed_empty);
    ASSERT_TRUE(opened_empty.has_value());
    EXPECT_TRUE(opened_empty->types.empty());

    int refused = 0;
    for (const auto& refusal : vector.at("refusals")) {
        EXPECT_EQ(test::error_of(open_manifest(vector_header(refusal.at("header").get<std::string>()), hex_field(refusal, "sealed"))),
            error_named(refusal.at("error").get<std::string>()))
            << refusal.at("name").get<std::string>();
        ++refused;
    }
    EXPECT_EQ(refused, 5);
}

TEST(VaultManifest, SealsOnlyCanonicalTypesAtOneSize)
{
    const auto& opened = first_opened();
    const auto full = types_up_to(wire::manifest_types_bound);
    const auto sealed = seal_manifest(opened, full);
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->size(), sealed_manifest_size);
    const auto manifest = open_manifest(opened, *sealed);
    ASSERT_TRUE(manifest.has_value());
    EXPECT_EQ(manifest->types, full);
    EXPECT_EQ(must(seal_manifest(opened, {})).size(), sealed_manifest_size);

    auto unordered = types_up_to(2);
    std::ranges::reverse(unordered);
    auto empty_type = types_up_to(2);
    empty_type.at(1).count = 0;
    for (const auto& refused : {types_up_to(wire::manifest_types_bound + 1), unordered, empty_type}) {
        EXPECT_EQ(test::error_of(seal_manifest(opened, refused)), Error::invalid_parameters);
    }
    EXPECT_EQ(test::error_of(open_manifest(opened, ByteView(*sealed).first(sealed_manifest_size - 1))), Error::integrity);
    auto longer = *sealed;
    longer.push_back(0);
    EXPECT_EQ(test::error_of(open_manifest(opened, longer)), Error::integrity);

    const auto next = vector_header("keystore_next");
    EXPECT_EQ(test::error_of(open_manifest(next, *sealed)), Error::integrity);
    const auto under_next = seal_manifest(next, full);
    ASSERT_TRUE(under_next.has_value());
    const auto opened_next = open_manifest(next, *under_next);
    ASSERT_TRUE(opened_next.has_value());
    EXPECT_EQ(opened_next->epoch, 2U);
    EXPECT_EQ(test::error_of(open_manifest(opened, *under_next)), Error::integrity);
    const auto other = first_header(master_of(header_vector("keystore_first")));
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(test::error_of(open_manifest(*other, *sealed)), Error::integrity);
}

Root random_root()
{
    const auto bytes = test::random_bytes_of(wire::manifest_root_size);
    Root root{};
    std::ranges::copy(bytes, root.begin());
    return root;
}

RecordAddress random_address()
{
    return RecordAddress{.type = *rc::gen::inRange<std::uint8_t>(1, 0xff),
        .id = *rc::gen::container<Bytes>(*rc::gen::inRange<std::size_t>(0, record_id_bound + 1), rc::gen::arbitrary<std::uint8_t>()),
        .counter = *rc::gen::arbitrary<std::uint64_t>()};
}

Nonce random_nonce()
{
    return array_of<crypto::aead_nonce_size>(test::random_bytes_of(crypto::aead_nonce_size));
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

RC_GTEST_PROP(VaultRecordProperties, TermsMatchAnIndependentHmac, ())
{
    const auto& keys = vector_keys();
    const auto address = random_address();
    const auto nonce = random_nonce();
    const auto expected = independent_term(address, nonce);
    RC_ASSERT(must(root_term(keys, address, nonce)) == expected);
    RC_ASSERT(must(must(TermHasher::of(keys)).term(address, nonce)) == expected);
}

RC_GTEST_PROP(VaultRecordProperties, RecordsRoundTripAndRefuseAnyFlippedBit, ())
{
    const auto& keys = vector_keys();
    const auto address = random_address();
    const auto payload = *rc::gen::container<Bytes>(*rc::gen::inRange<std::size_t>(0, 2048), rc::gen::arbitrary<std::uint8_t>());
    const auto record = must(seal_record(keys, address, payload));
    const auto bucket = record.size() - crypto::aead_overhead;
    RC_ASSERT(std::ranges::contains(record_buckets, bucket));
    RC_ASSERT(payload.size() < bucket);
    RC_ASSERT(bucket == record_buckets.front() || payload.size() >= bucket / 2);
    const auto nonce = must(nonce_of(record));
    const auto opened = open_record(keys, address, nonce, record);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(opened->equals(payload));
    const auto flipped = test::flip_random_bit(record);
    const auto refused = open_record(keys, address, must(nonce_of(flipped)), flipped);
    RC_ASSERT(!refused.has_value());
    RC_ASSERT(refused.error() == Error::integrity);
}

RC_GTEST_PROP(VaultRecordProperties, AddressesRoundTripUnderAnySlot, ())
{
    const auto& keys = vector_keys();
    const Located located{.address = random_address(), .nonce = random_nonce()};
    const auto slot = *rc::gen::inRange<std::uint64_t>(1, slot_bound);
    const auto sealed = must(seal_address(keys, slot, located));
    SecretBytes scratch;
    const auto opened = open_address(keys, slot, sealed, scratch);
    RC_ASSERT(opened.has_value());
    RC_ASSERT(opened->address.type == located.address.type);
    RC_ASSERT(opened->address.id == located.address.id);
    RC_ASSERT(opened->address.counter == located.address.counter);
    RC_ASSERT(opened->nonce == located.nonce);
    const auto refused = open_address(keys, slot, test::flip_random_bit(sealed), scratch);
    RC_ASSERT(!refused.has_value());
    RC_ASSERT(refused.error() == Error::integrity);
}

}
}
