// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/vault/keys.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/pwhash.hpp"
#include "lume/crypto/random.hpp"
#include "lume/wire/codec.hpp"
#include "vault/vault_internal.hpp"

#include <algorithm>
#include <span>
#include <utility>

namespace lume::vault {
namespace {

using crypto::SecretBytes;

constexpr crypto::ByteArray<key_size> zero_salt{};
constexpr std::uint8_t continuation_mask = 0xc0;
constexpr std::uint8_t continuation_bits = 0x80;

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

bool consistent(wire::HardwareMode mode, const std::optional<TpmPoint>& tpm_point) noexcept
{
    if (!known_mode(mode) || tpm_point.has_value() != (mode == wire::HardwareMode::tpm)) {
        return false;
    }
    return !tpm_point || tpm_point->front() == wire::tpm_point_uncompressed;
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

}

bool within_bounds(Cost cost) noexcept
{
    return cost.ops >= cost_floor.ops && cost.ops <= cost_ceiling.ops && cost.mem >= cost_floor.mem
        && cost.mem <= cost_ceiling.mem;
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

Result<SecretBytes> derive_passphrase_key(std::string_view passphrase, const Salt& salt, Cost cost)
{
    if (!within_bounds(cost)) {
        return std::unexpected(Error::integrity);
    }
    if (passphrase.size() > passphrase_bound) {
        return std::unexpected(Error::invalid_passphrase);
    }
    auto key = crypto::argon2id(passphrase, salt, cost.ops, cost.mem);
    if (!key) {
        return std::unexpected(Error::library_failure);
    }
    return std::move(*key);
}

Result<SecretBytes> derive_tpm_authorisation(const SecretBytes& passphrase_key)
{
    return expand(zero_salt, passphrase_key, "vault/tpm-pin");
}

Result<SecretBytes> derive_tpm_hardware_key(const SecretBytes& shared_secret)
{
    if (shared_secret.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    return crypto::sha256_secret({crypto::label("vault/tpm"), shared_secret.view()});
}

Result<SecretBytes> derive_master_key(const SecretBytes& passphrase_key, const SecretBytes& hardware_key)
{
    if (hardware_key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    return expand(hardware_key.view(), passphrase_key, "vault/master");
}

Result<Keys> keys_of(SecretBytes data_key)
{
    if (data_key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    auto record = expand(zero_salt, data_key, "vault/record-key");
    auto manifest = expand(zero_salt, data_key, "vault/manifest-key");
    auto root = expand(zero_salt, data_key, "vault/root-key");
    if (!record || !manifest || !root) {
        return std::unexpected(Error::library_failure);
    }
    return Keys{
        .data = std::move(data_key),
        .record = std::move(*record),
        .manifest = std::move(*manifest),
        .root = std::move(*root)};
}

Result<Keys> fresh_keys()
{
    return keys_of(crypto::random_secret(key_size));
}

Result<wire::VaultHeader> seal_header(const SecretBytes& master_key, const Keys& keys, const Protection& protection)
{
    return detail::seal_header(master_key, keys, protection, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<Keys> open_header(const SecretBytes& master_key, const wire::VaultHeader& header)
{
    if (!within_bounds(Cost{.ops = header.ops, .mem = header.mem}) || !consistent(header.hw_mode, header.tpm_point)) {
        return std::unexpected(Error::integrity);
    }
    const auto check = check_of(master_key, header);
    if (!check) {
        return std::unexpected(check.error());
    }
    auto data_key = crypto::aead_open(master_key, crypto::label("vault/data-key"), header.wrapped_data_key);
    const bool unwraps = data_key.has_value() && data_key->size() == key_size;
    if (!check->equals(header.check)) {
        return std::unexpected(unwraps ? Error::integrity : Error::wrong_passphrase);
    }
    if (!unwraps) {
        return std::unexpected(Error::integrity);
    }
    return keys_of(std::move(*data_key));
}

namespace detail {

Result<wire::VaultHeader> seal_header(
    const SecretBytes& master_key, const Keys& keys, const Protection& protection, const Nonce& nonce)
{
    if (master_key.size() != key_size || keys.data.size() != key_size || !within_bounds(protection.cost)
        || !consistent(protection.hw_mode, protection.tpm_point)) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto wrapped = crypto::detail::aead_encrypt(master_key, nonce, crypto::label("vault/data-key"), keys.data.view());
    if (!wrapped || nonce.size() + wrapped->size() != wire::wrapped_data_key_size) {
        return std::unexpected(Error::library_failure);
    }
    wire::VaultHeader header{
        .salt = protection.salt,
        .ops = protection.cost.ops,
        .mem = protection.cost.mem,
        .hw_mode = protection.hw_mode,
        .tpm_point = protection.tpm_point,
        .wrapped_data_key = {},
        .epoch = protection.epoch,
        .check = {}};
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

}

}
