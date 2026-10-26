// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>

namespace lume::crypto::detail {

inline constexpr std::size_t mlkem768_encapsulation_randomness_size = 32;

[[nodiscard]] Result<MlKemEncapsulation> mlkem768_encapsulate_deterministic(
    ByteView public_key, const SecretBytes& randomness);

}
