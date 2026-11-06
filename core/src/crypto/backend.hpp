// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"

#include <cstdint>
#include <span>

namespace lume::crypto::detail {

[[nodiscard]] Result<void> operational_state();

void require_operational();

void throw_unless_operational(const Result<void>& state);

void wipe(std::span<std::uint8_t> bytes) noexcept;

[[nodiscard]] bool is_zero(ByteView bytes) noexcept;

[[nodiscard]] inline const std::uint8_t* pointer_to(ByteView bytes) noexcept
{
    static constexpr std::uint8_t nothing = 0;
    return bytes.empty() ? &nothing : bytes.data();
}

}
