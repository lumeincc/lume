// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

namespace lume::vault {

inline constexpr std::size_t hardware_secret_size = 32;
inline constexpr std::size_t key_inventory_bound = 16;

using TpmPoint = crypto::ByteArray<wire::tpm_point_size>;

struct KeyName {
    wire::HardwareMode mode = wire::HardwareMode::software;
    std::uint64_t epoch = 0;
    std::optional<TpmPoint> point;

    friend bool operator==(const KeyName&, const KeyName&) = default;
};

enum class HardwareError : std::uint8_t {
    key_missing = 1,
    authorisation_failed = 2,
    lockout = 3,
    unavailable = 4,
    unsupported = 5,
    mismatch = 6,
    exists = 7,
    failure = 8,
};

template <typename T>
using HardwareResult = std::expected<T, HardwareError>;

}
