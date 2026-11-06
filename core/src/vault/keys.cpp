// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/keys.hpp"

#include "crypto/aead_internal.hpp"
#include "crypto/backend.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/pwhash.hpp"
#include "lume/crypto/random.hpp"
#include "lume/wire/codec.hpp"
#include "vault/key_access.hpp"
#include "vault/vault_internal.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <span>
#include <utility>

namespace lume::vault {
namespace {

using crypto::SecretBytes;
using detail::KeyAccess;

constexpr crypto::ByteArray<key_size> zero_salt{};
constexpr std::uint8_t continuation_mask = 0xc0;
constexpr std::uint8_t continuation_bits = 0x80;
constexpr std::uint64_t last_epoch = std::numeric_limits<std::uint64_t>::max();

Result<SecretBytes> expand(crypto::ByteView salt, const SecretBytes& input, std::string_view name)
{
    if (input.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    auto key = crypto::hkdf_sha256(salt, input.view(), crypto::label(name), key_size);
    if (!key) {
        return std::unexpected(Error::library_failure);
    }
    return std::move(*key);
}

Result<SecretBytes> input_for(const SecretBytes& passphrase_key, wire::HardwareMode mode)
{
    if (passphrase_key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    switch (mode) {
    case wire::HardwareMode::keystore:
        return expand(zero_salt, passphrase_key, "vault/keystore");
    case wire::HardwareMode::tpm:
        return expand(zero_salt, passphrase_key, "vault/tpm-pin");
    case wire::HardwareMode::software:
        return SecretBytes{};
    }
    return std::unexpected(Error::invalid_parameters);
}

Result<SecretBytes> master_of(const SecretBytes& hardware_secret, const SecretBytes& passphrase_key)
{
    if (hardware_secret.size() != hardware_secret_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    return expand(hardware_secret.view(), passphrase_key, "vault/master");
}

bool known_mode(wire::HardwareMode mode) noexcept
{
    switch (mode) {
    case wire::HardwareMode::keystore:
    case wire::HardwareMode::tpm:
    case wire::HardwareMode::software:
        return true;
    }
    return false;
}

bool point_matches_mode(wire::HardwareMode mode, const std::optional<TpmPoint>& point) noexcept
{
    if (point.has_value() != (mode == wire::HardwareMode::tpm)) {
        return false;
    }
    return !point || point->front() == wire::tpm_point_uncompressed;
}

bool well_formed_name(const KeyName& name) noexcept
{
    return known_mode(name.mode) && name.epoch >= first_epoch && point_matches_mode(name.mode, name.point);
}

bool valid_ceiling(Cost ceiling) noexcept
{
    return ceiling.ops >= cost_floor.ops && ceiling.ops <= cost_ceiling.ops && ceiling.mem >= cost_floor.mem
        && ceiling.mem <= cost_ceiling.mem;
}

Cost cost_of(const wire::VaultHeader& header) noexcept
{
    return Cost{.ops = header.ops, .mem = header.mem};
}

Result<Keys> keys_of(SecretBytes data_key)
{
    if (data_key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    auto record = expand(zero_salt, data_key, "vault/record-key");
    auto address = expand(zero_salt, data_key, "vault/address-key");
    auto manifest = expand(zero_salt, data_key, "vault/manifest-key");
    auto root = expand(zero_salt, data_key, "vault/root-key");
    if (!record || !address || !manifest || !root) {
        return std::unexpected(Error::library_failure);
    }
    return KeyAccess::keys(
        std::move(data_key), std::move(*record), std::move(*address), std::move(*manifest), std::move(*root));
}

Result<SecretBytes> check_of(const SecretBytes& master_key, const wire::VaultHeader& header)
{
    const auto check_key = expand(zero_salt, master_key, "vault/check-key");
    if (!check_key) {
        return std::unexpected(check_key.error());
    }
    return crypto::hmac_sha256(
        check_key->view(), crypto::Encoder{}.label("vault/check").raw(wire::encode_unsigned(header)).take());
}

struct Unwrapped {
    bool check_matches = false;
    std::optional<SecretBytes> data_key;
};

Result<Unwrapped> unwrap(const SecretBytes& master_key, const wire::VaultHeader& header)
{
    const auto check = check_of(master_key, header);
    if (!check) {
        return std::unexpected(check.error());
    }
    Unwrapped result;
    result.check_matches = check->equals(header.check);
    auto data_key = crypto::aead_open(master_key, crypto::label("vault/data-key"), header.wrapped_data_key);
    if (data_key.has_value() && data_key->size() == key_size) {
        result.data_key = std::move(*data_key);
    }
    return result;
}

bool bound_to(const MasterKey& master_key, const wire::VaultHeader& header) noexcept
{
    return master_key.salt() == header.salt && master_key.cost() == cost_of(header)
        && names(header, master_key.hardware());
}

Result<wire::VaultHeader> seal(const SecretBytes& master_key, const SecretBytes& data_key, const Salt& salt, Cost cost,
    const KeyName& hardware, std::uint64_t epoch, const detail::Nonce& nonce)
{
    if (master_key.size() != key_size || data_key.size() != key_size || !within_bounds(cost, cost_ceiling)) {
        return std::unexpected(Error::invalid_parameters);
    }
    wire::VaultHeader header{
        .salt = salt,
        .ops = cost.ops,
        .mem = cost.mem,
        .hw_mode = hardware.mode,
        .tpm_point = hardware.point,
        .wrapped_data_key = {},
        .epoch = epoch,
        .check = {}};
    if (!well_formed(header)) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto wrapped = crypto::detail::aead_encrypt(master_key, nonce, crypto::label("vault/data-key"), data_key.view());
    if (!wrapped || nonce.size() + wrapped->size() != wire::wrapped_data_key_size) {
        return std::unexpected(Error::library_failure);
    }
    const std::span wrapped_data_key(header.wrapped_data_key);
    std::ranges::copy(nonce, wrapped_data_key.begin());
    std::ranges::copy(*wrapped, wrapped_data_key.subspan(nonce.size()).begin());
    const auto check = check_of(master_key, header);
    if (!check) {
        return std::unexpected(check.error());
    }
    std::ranges::copy(check->view(), header.check.begin());
    return header;
}

Result<OpenedHeader> written(Result<wire::VaultHeader> header, const SecretBytes& data_key, const KeyName& hardware)
{
    if (!header) {
        return std::unexpected(header.error());
    }
    auto keys = keys_of(data_key.clone());
    if (!keys) {
        return std::unexpected(keys.error());
    }
    return KeyAccess::opened_header(*header, std::move(*keys), SecretBytes{}, hardware);
}

}

const Salt& PassphraseKey::salt() const noexcept
{
    return salt_;
}

Cost PassphraseKey::cost() const noexcept
{
    return cost_;
}

PassphraseKey::PassphraseKey(SecretBytes key, const Salt& salt, Cost cost) noexcept
    : key_(std::move(key))
    , salt_(salt)
    , cost_(cost)
{
}

const KeyName& HardwareKey::name() const noexcept
{
    return name_;
}

HardwareKey::HardwareKey(SecretBytes key, const KeyName& name) noexcept
    : key_(std::move(key))
    , name_(name)
{
}

const Salt& MasterKey::salt() const noexcept
{
    return salt_;
}

Cost MasterKey::cost() const noexcept
{
    return cost_;
}

const KeyName& MasterKey::hardware() const noexcept
{
    return hardware_;
}

MasterKey::MasterKey(SecretBytes key, SecretBytes passphrase, const Salt& salt, Cost cost, const KeyName& hardware) noexcept
    : key_(std::move(key))
    , passphrase_(std::move(passphrase))
    , salt_(salt)
    , cost_(cost)
    , hardware_(hardware)
{
}

Keys::Keys(SecretBytes data, SecretBytes record, SecretBytes address, SecretBytes manifest, SecretBytes root) noexcept
    : data_(std::move(data))
    , record_(std::move(record))
    , address_(std::move(address))
    , manifest_(std::move(manifest))
    , root_(std::move(root))
{
}

const wire::VaultHeader& OpenedHeader::header() const noexcept
{
    return header_;
}

const Keys& OpenedHeader::keys() const noexcept
{
    return keys_;
}

const KeyName& OpenedHeader::hardware() const noexcept
{
    return hardware_;
}

void OpenedHeader::forget_passphrase() noexcept
{
    passphrase_ = SecretBytes{};
}

OpenedHeader::OpenedHeader(const wire::VaultHeader& header, Keys keys, SecretBytes passphrase, const KeyName& hardware) noexcept
    : header_(header)
    , keys_(std::move(keys))
    , passphrase_(std::move(passphrase))
    , hardware_(hardware)
{
}

const Check& Confirmed::check() const noexcept
{
    return check_;
}

Confirmed::Confirmed(const Check& check) noexcept
    : check_(check)
{
}

std::optional<Limits> limits_of(Platform platform) noexcept
{
    switch (platform) {
    case Platform::android:
        return android_limits;
    case Platform::desktop:
        return desktop_limits;
    }
    return std::nullopt;
}

bool within_bounds(Cost cost, Cost ceiling) noexcept
{
    return valid_ceiling(ceiling) && cost.ops >= cost_floor.ops && cost.ops <= ceiling.ops && cost.mem >= cost_floor.mem
        && cost.mem <= ceiling.mem;
}

bool rotates(wire::HardwareMode mode) noexcept
{
    return mode == wire::HardwareMode::keystore || mode == wire::HardwareMode::software;
}

bool well_formed(const wire::VaultHeader& header) noexcept
{
    return known_mode(header.hw_mode) && point_matches_mode(header.hw_mode, header.tpm_point) && header.epoch >= first_epoch;
}

bool names(const wire::VaultHeader& header, const KeyName& key) noexcept
{
    if (key.mode != header.hw_mode) {
        return false;
    }
    if (rotates(header.hw_mode)) {
        return key.epoch == header.epoch;
    }
    return key.point.has_value() && key.point == header.tpm_point;
}

Result<void> check_new_passphrase(std::string_view passphrase, wire::HardwareMode mode)
{
    const auto minimum = mode == wire::HardwareMode::software ? software_passphrase_minimum : passphrase_minimum;
    if (passphrase.size() > passphrase_bound) {
        return std::unexpected(Error::invalid_passphrase);
    }
    if (passphrase.size() < minimum) {
        return std::unexpected(Error::passphrase_too_short);
    }
    SecretBytes bytes(passphrase.size());
    std::ranges::transform(passphrase, bytes.writable().begin(), [](char unit) { return static_cast<std::uint8_t>(unit); });
    if (!wire::is_valid_text(bytes.view())) {
        return std::unexpected(Error::invalid_passphrase);
    }
    const auto code_points = std::ranges::count_if(
        bytes.view(), [](std::uint8_t unit) { return (unit & continuation_mask) != continuation_bits; });
    if (std::cmp_less(code_points, minimum)) {
        return std::unexpected(Error::passphrase_too_short);
    }
    return {};
}

Salt fresh_salt()
{
    return crypto::random_public_bytes<wire::vault_salt_size>();
}

Result<PassphraseKey> derive_passphrase_key(std::string_view passphrase, const Salt& salt, Cost cost, Platform platform)
{
    const auto limits = limits_of(platform);
    if (!limits) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (!within_bounds(cost, limits->ceiling)) {
        return std::unexpected(Error::integrity);
    }
    if (passphrase.size() > passphrase_bound) {
        return std::unexpected(Error::invalid_passphrase);
    }
    auto key = crypto::argon2id(passphrase, salt, cost.ops, cost.mem);
    if (!key) {
        return std::unexpected(Error::library_failure);
    }
    return KeyAccess::passphrase_key(std::move(*key), salt, cost);
}

Result<SecretBytes> hardware_input(const PassphraseKey& passphrase_key, wire::HardwareMode mode)
{
    return input_for(KeyAccess::secret(passphrase_key), mode);
}

Result<SecretBytes> hardware_input(const OpenedHeader& opened)
{
    return input_for(KeyAccess::passphrase(opened), opened.header().hw_mode);
}

Result<HardwareKey> hardware_key(const KeyName& name, crypto::ByteView output)
{
    if (!well_formed_name(name)) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (output.size() != hardware_secret_size || crypto::detail::is_zero(output)) {
        return std::unexpected(Error::hardware_failure);
    }
    auto key = name.mode == wire::HardwareMode::tpm ? crypto::sha256_secret({crypto::label("vault/tpm"), output})
                                                    : SecretBytes::copy_of(output);
    return KeyAccess::hardware_key(std::move(key), name);
}

Result<MasterKey> derive_master_key(const PassphraseKey& passphrase_key, const HardwareKey& hardware_key)
{
    auto key = master_of(KeyAccess::secret(hardware_key), KeyAccess::secret(passphrase_key));
    if (!key) {
        return std::unexpected(key.error());
    }
    return KeyAccess::master_key(std::move(*key), KeyAccess::secret(passphrase_key).clone(), passphrase_key.salt(),
        passphrase_key.cost(), hardware_key.name());
}

Result<OpenedHeader> first_header(const MasterKey& master_key)
{
    return detail::first_header(
        master_key, crypto::random_secret(key_size), crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<OpenedHeader> open_header(const MasterKey& master_key, const wire::VaultHeader& header)
{
    if (!well_formed(header) || !within_bounds(cost_of(header), cost_ceiling)) {
        return std::unexpected(Error::integrity);
    }
    if (!bound_to(master_key, header)) {
        return std::unexpected(Error::invalid_parameters);
    }
    auto unwrapped = unwrap(KeyAccess::secret(master_key), header);
    if (!unwrapped) {
        return std::unexpected(unwrapped.error());
    }
    if (!unwrapped->check_matches) {
        return std::unexpected(unwrapped->data_key ? Error::integrity : Error::wrong_passphrase);
    }
    if (!unwrapped->data_key) {
        return std::unexpected(Error::integrity);
    }
    auto keys = keys_of(std::move(*unwrapped->data_key));
    if (!keys) {
        return std::unexpected(keys.error());
    }
    return KeyAccess::opened_header(
        header, std::move(*keys), KeyAccess::passphrase(master_key).clone(), master_key.hardware());
}

Result<Keys> salvage_keys(const MasterKey& master_key, const wire::VaultHeader& header)
{
    if (!well_formed(header) || !within_bounds(cost_of(header), cost_ceiling)) {
        return std::unexpected(Error::integrity);
    }
    if (!bound_to(master_key, header)) {
        return std::unexpected(Error::invalid_parameters);
    }
    auto unwrapped = unwrap(KeyAccess::secret(master_key), header);
    if (!unwrapped) {
        return std::unexpected(unwrapped.error());
    }
    if (!unwrapped->data_key) {
        return std::unexpected(unwrapped->check_matches ? Error::integrity : Error::wrong_passphrase);
    }
    if (unwrapped->check_matches) {
        return std::unexpected(Error::invalid_parameters);
    }
    return keys_of(std::move(*unwrapped->data_key));
}

Result<Confirmed> confirm(const MasterKey& master_key, const OpenedHeader& current)
{
    const auto opened_again = open_header(master_key, current.header());
    if (!opened_again) {
        return std::unexpected(opened_again.error());
    }
    if (!KeyAccess::data(opened_again->keys()).equals(KeyAccess::data(current.keys()).view())) {
        return std::unexpected(Error::integrity);
    }
    return KeyAccess::confirmed(current.header().check);
}

Result<OpenedHeader> next_header(const HardwareKey& hardware_key, const OpenedHeader& current)
{
    return detail::next_header(hardware_key, current, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<OpenedHeader> rekeyed_header(const MasterKey& master_key, const OpenedHeader& current, const Confirmed& confirmed)
{
    return detail::rekeyed_header(
        master_key, current, confirmed, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

namespace detail {

Result<OpenedHeader> first_header(const MasterKey& master_key, const SecretBytes& data_key, const Nonce& nonce)
{
    const auto& hardware = master_key.hardware();
    if (hardware.epoch != first_epoch || data_key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    return written(seal(KeyAccess::secret(master_key), data_key, master_key.salt(), master_key.cost(), hardware, first_epoch, nonce),
        data_key, hardware);
}

Result<OpenedHeader> next_header(const HardwareKey& hardware_key, const OpenedHeader& current, const Nonce& nonce)
{
    const auto& header = current.header();
    const auto& name = hardware_key.name();
    if (name.mode != header.hw_mode) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (header.epoch == last_epoch) {
        return std::unexpected(Error::integrity);
    }
    const bool follows = rotates(header.hw_mode) ? name.epoch == header.epoch + 1
                                                 : name.point.has_value() && name.point == header.tpm_point;
    if (!follows) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto& passphrase = KeyAccess::passphrase(current);
    const auto master_key = master_of(KeyAccess::secret(hardware_key), passphrase);
    if (!master_key) {
        return std::unexpected(master_key.error());
    }
    const auto& data_key = KeyAccess::data(current.keys());
    return written(seal(*master_key, data_key, header.salt, cost_of(header), name, header.epoch + 1, nonce), data_key, name);
}

Result<OpenedHeader> rekeyed_header(
    const MasterKey& master_key, const OpenedHeader& current, const Confirmed& confirmed, const Nonce& nonce)
{
    const auto& header = current.header();
    const auto& name = master_key.hardware();
    if (confirmed.check() != header.check || master_key.salt() == header.salt || name.mode != header.hw_mode) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (header.epoch == last_epoch) {
        return std::unexpected(Error::integrity);
    }
    if (name.epoch != header.epoch + 1 || (name.mode == wire::HardwareMode::tpm && name.point == header.tpm_point)) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto& data_key = KeyAccess::data(current.keys());
    return written(seal(KeyAccess::secret(master_key), data_key, master_key.salt(), master_key.cost(), name,
                       header.epoch + 1, nonce),
        data_key, name);
}

}

}
