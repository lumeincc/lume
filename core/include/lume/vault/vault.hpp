// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

namespace lume::vault {

inline constexpr std::size_t passphrase_bound = 1024;
inline constexpr std::size_t passphrase_minimum = 10;
inline constexpr std::size_t software_passphrase_minimum = 14;
inline constexpr std::size_t record_id_bound = 64;
inline constexpr std::size_t payload_bound = std::size_t{128} * 1024 - 1;

enum class Error : std::uint8_t {
    wrong_passphrase = 1,
    integrity = 2,
    invalid_parameters = 3,
    passphrase_too_short = 4,
    invalid_passphrase = 5,
    record_too_large = 6,
    library_failure = 7,
    no_vault = 8,
    vault_exists = 9,
    wiped = 10,
    unsupported_version = 11,
    busy = 12,
    locked = 13,
    broken = 14,
    rollback = 15,
    hardware_key_missing = 16,
    hardware_lockout = 17,
    hardware_unavailable = 18,
    hardware_unsupported = 19,
    hardware_failure = 20,
    storage_full = 21,
    storage = 22,
};

template <typename T>
using Result = std::expected<T, Error>;

enum class Platform : std::uint8_t {
    android = 1,
    desktop = 2,
};

using RecordType = std::uint8_t;

}
