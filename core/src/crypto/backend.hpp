// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstdint>

namespace lume::crypto::detail {

void ensure_backends_ready();

[[nodiscard]] inline const std::uint8_t* pointer_to(ByteView bytes) noexcept
{
    static constexpr std::uint8_t nothing = 0;
    return bytes.empty() ? &nothing : bytes.data();
}

}
