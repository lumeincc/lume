// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

namespace lume::vault {

inline constexpr std::uint32_t kib_per_mib = 1024;
inline constexpr std::size_t key_size = 32;
inline constexpr std::size_t passphrase_bound = 1024;
inline constexpr std::size_t passphrase_minimum = 10;
inline constexpr std::size_t software_passphrase_minimum = 14;

struct Cost {
    std::uint32_t ops = 0;
    std::uint32_t mem = 0;
};

inline constexpr Cost android_cost{.ops = 3, .mem = 64 * kib_per_mib};
inline constexpr Cost desktop_cost{.ops = 3, .mem = 256 * kib_per_mib};
inline constexpr Cost cost_floor{.ops = 2, .mem = 64 * kib_per_mib};
inline constexpr Cost cost_ceiling{.ops = 10, .mem = 1024 * kib_per_mib};

enum class Error : std::uint8_t {
    wrong_passphrase,
    integrity,
    invalid_parameters,
    passphrase_too_short,
    invalid_passphrase,
    record_too_large,
    library_failure,
};

template <typename T>
using Result = std::expected<T, Error>;

using Salt = crypto::ByteArray<wire::vault_salt_size>;
using TpmPoint = crypto::ByteArray<wire::tpm_point_size>;

struct Keys {
    crypto::SecretBytes data;
    crypto::SecretBytes record;
    crypto::SecretBytes manifest;
    crypto::SecretBytes root;
};

struct Protection {
    Salt salt{};
    Cost cost{};
    wire::HardwareMode hw_mode = wire::HardwareMode::software;
    std::optional<TpmPoint> tpm_point;
    std::uint64_t epoch = 0;
};

[[nodiscard]] bool within_bounds(Cost cost) noexcept;

[[nodiscard]] Result<void> check_new_passphrase(std::string_view passphrase, wire::HardwareMode mode);

[[nodiscard]] Salt fresh_salt();

[[nodiscard]] Result<crypto::SecretBytes> derive_passphrase_key(std::string_view passphrase, const Salt& salt, Cost cost);

[[nodiscard]] Result<crypto::SecretBytes> derive_tpm_authorisation(const crypto::SecretBytes& passphrase_key);

[[nodiscard]] Result<crypto::SecretBytes> derive_tpm_hardware_key(const crypto::SecretBytes& shared_secret);

[[nodiscard]] Result<crypto::SecretBytes> derive_master_key(
    const crypto::SecretBytes& passphrase_key, const crypto::SecretBytes& hardware_key);

[[nodiscard]] Result<Keys> keys_of(crypto::SecretBytes data_key);

[[nodiscard]] Result<Keys> fresh_keys();

[[nodiscard]] Result<wire::VaultHeader> seal_header(
    const crypto::SecretBytes& master_key, const Keys& keys, const Protection& protection);

[[nodiscard]] Result<Keys> open_header(const crypto::SecretBytes& master_key, const wire::VaultHeader& header);

}
