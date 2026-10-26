// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <cstdint>
#include <expected>

namespace lume::crypto {

enum class Error : std::uint8_t {
    invalid_size,
    invalid_key,
    weak_public_key,
    authentication_failed,
    self_test_failed,
    library_failure,
};

template <typename T>
using Result = std::expected<T, Error>;

}
