// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/seal/seal.hpp"

#include <cstdint>
#include <functional>
#include <span>

namespace lume::seal::detail {

using RandomSource = std::function<void(std::span<std::uint8_t>)>;

[[nodiscard]] Result<wire::Seal> seal(
    const wire::PrekeyX& seal_key, const wire::Inner& inner, const RandomSource& random);

[[nodiscard]] Result<wire::Inner> inner_of(crypto::ByteView padded);

}
