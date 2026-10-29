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
    const Recipient& recipient, const wire::Inner& inner, std::uint64_t now, const RandomSource& random);

[[nodiscard]] Result<wire::Seal> seal_card(
    const Recipient& recipient, const wire::Card& card, std::uint64_t now, const RandomSource& random);

[[nodiscard]] Result<wire::Inner> inner_of(crypto::ByteView padded);

}
