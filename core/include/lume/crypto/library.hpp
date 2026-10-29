// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/error.hpp"

#include <cstddef>
#include <cstdint>

namespace lume::crypto {

inline constexpr std::size_t locked_memory_target = std::size_t{32} * 1024 * 1024;

struct MemoryLocking {
    bool limit_reaches_target = false;
    std::uint64_t failed_locks = 0;
};

[[nodiscard]] Result<void> initialise();

[[nodiscard]] MemoryLocking memory_locking();

}
